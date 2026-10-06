// SPDX-License-Identifier: MPL-2.0
//! Write-only webhooks for encrypted channels (ENCRYPTION.md §5b).
//!
//! Per conversation and epoch the members derive an X25519 **inbox key pair** from the epoch's content key
//! (`inbox_secret = HKDF-Expand(PRK = content_key, info = "tavrn webhook inbox v1", L = 32)`); a member device
//! publishes the public key with a device signature. A webhook message is a libsodium sealed box
//! (`crypto_box_seal`: X25519 + XSalsa20-Poly1305 with an ephemeral sender key) to that public key, so any
//! libsodium binding can seal and every reader of the epoch can open it, while the node and the sender cannot.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::util::put_str16;

/// HKDF info of the inbox secret key.
pub const INBOX_LABEL: &[u8] = b"tavrn webhook inbox v1";
/// Domain separation prefix of the device signature over a published inbox key.
pub const INBOX_SIGNATURE_CONTEXT: &[u8] = b"tavrn webhook inbox key v1\0";
/// The `algorithm` of an inbox key: libsodium's `crypto_box_seal`.
pub const ALGORITHM: &str = "x25519-xsalsa20poly1305-sealedbox";
/// Bytes a sealed box adds to its plaintext (ephemeral public key 32 + Poly1305 tag 16).
pub const SEAL_OVERHEAD: usize = 48;

/// The inbox secret key (X25519, unclamped bytes as libsodium stores them) of the epoch whose content key is
/// `content_key`.
pub fn inbox_secret(content_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    // A 32-byte PRK is always accepted and 32 output bytes are always within HKDF-SHA256's limit.
    if let Ok(hk) = Hkdf::<Sha256>::from_prk(content_key) {
        let _ = hk.expand(INBOX_LABEL, out.as_mut_slice());
    }
    out
}

/// The inbox public key of the epoch whose content key is `content_key`.
pub fn inbox_public_key(content_key: &[u8; 32]) -> [u8; 32] {
    crypto_box::SecretKey::from_bytes(*inbox_secret(content_key)).public_key().to_bytes()
}

/// What a device signs when it publishes an inbox key:
/// `"tavrn webhook inbox key v1" || 0x00 || str16(conversation) || u64(epoch) || public_key`.
pub fn inbox_signing_input(conversation: &str, epoch: u64, public_key: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(INBOX_SIGNATURE_CONTEXT.len() + 2 + conversation.len() + 8 + 32);
    msg.extend_from_slice(INBOX_SIGNATURE_CONTEXT);
    put_str16(&mut msg, conversation);
    msg.extend_from_slice(&epoch.to_be_bytes());
    msg.extend_from_slice(public_key);
    msg
}

/// Checks the device signature of a published inbox key (the node, ENCRYPTION.md §5b).
pub fn verify_inbox_key(
    device_key: &[u8; 32],
    conversation: &str,
    epoch: u64,
    public_key: &[u8; 32],
    signature: &[u8],
) -> Result<()> {
    let key = VerifyingKey::from_bytes(device_key).map_err(|_| CryptoError::InvalidInput("device key"))?;
    let signature = Signature::from_slice(signature).map_err(|_| CryptoError::BadSignature)?;
    key.verify(&inbox_signing_input(conversation, epoch, public_key), &signature).map_err(|_| CryptoError::BadSignature)
}

/// `crypto_box_seal(plaintext, public_key)`: what a webhook sender (or the node in `node` mode) does.
pub fn seal(public_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    seal_with_rng(&mut OsRng, public_key, plaintext)
}

pub(crate) fn seal_with_rng(
    rng: &mut (impl RngCore + CryptoRng),
    public_key: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    crypto_box::PublicKey::from_bytes(*public_key)
        .seal(rng, plaintext)
        .map_err(|_| CryptoError::InvalidInput("plaintext too large"))
}

/// `crypto_box_seal_open` with the inbox key of the epoch whose content key is `content_key`.
pub fn open(content_key: &[u8; 32], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < SEAL_OVERHEAD {
        return Err(CryptoError::DecryptionFailed);
    }
    let secret = crypto_box::SecretKey::from_bytes(*inbox_secret(content_key));
    secret.unseal(sealed).map(Zeroizing::new).map_err(|_| CryptoError::DecryptionFailed)
}

/// An RNG that hands out fixed bytes (test vectors only: the ephemeral key of a sealed box).
#[cfg(test)]
pub(crate) struct FixedRng(pub [u8; 32]);

#[cfg(test)]
impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }
    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.copy_from_slice(&self.0[..dest.len()]);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[cfg(test)]
impl CryptoRng for FixedRng {}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use crate::device::Device;

    #[test]
    fn sealed_boxes_open_only_with_the_epoch_key() {
        let key = [7u8; 32];
        let other = [8u8; 32];
        let pk = inbox_public_key(&key);
        assert_ne!(pk, inbox_public_key(&other), "every epoch has its own pair");
        assert_ne!(pk.as_slice(), inbox_secret(&key).as_slice());
        let sealed = seal(&pk, b"{\"content\":{}}").expect("seal");
        assert_eq!(sealed.len(), 14 + SEAL_OVERHEAD);
        assert_ne!(seal(&pk, b"{\"content\":{}}").expect("seal"), sealed, "fresh ephemeral key per box");
        assert_eq!(open(&key, &sealed).expect("open").as_slice(), b"{\"content\":{}}");
        assert!(matches!(open(&other, &sealed), Err(CryptoError::DecryptionFailed)));
        let mut tampered = sealed.clone();
        tampered[40] ^= 1;
        assert!(open(&key, &tampered).is_err());
        assert!(open(&key, &sealed[..47]).is_err());
    }

    #[test]
    fn opens_a_box_sealed_by_libsodium() {
        // `crypto_box_seal("hello from libsodium", pk)` by libsodium-wrappers 0.8 for the inbox key of the content
        // key 0x40..0x5f (protocol/testvectors/encryption.json, `webhook_inbox`).
        let content_key: [u8; 32] = std::array::from_fn(|i| 64 + i as u8);
        let sealed = crate::util::b64url_decode(
            "46gMX_6CvkHcDXXXgazthioV_QcGhSEQcqliKCl0qmRe2cTltkM4mKfINF3C2VL_Dwns7VNADnz2VuLgKjIUGWAk_xg",
        )
        .expect("b64");
        assert_eq!(open(&content_key, &sealed).expect("open").as_slice(), b"hello from libsodium");
    }

    #[test]
    fn inbox_key_signatures_bind_conversation_epoch_and_key() {
        let device = Device::from_secret("alice@node.example", "01J9ZK3G5M8Q2W4E6R8T0Y2VA1", &[3u8; 32]).expect("dev");
        let conv = "node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V00";
        let pk = inbox_public_key(&[1u8; 32]);
        let sig = device.sign_raw(&inbox_signing_input(conv, 5, &pk));
        let dk = device.public_key();
        verify_inbox_key(&dk, conv, 5, &pk, &sig).expect("valid");
        assert!(verify_inbox_key(&dk, conv, 6, &pk, &sig).is_err());
        assert!(verify_inbox_key(&dk, "node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V01", 5, &pk, &sig).is_err());
        assert!(verify_inbox_key(&dk, conv, 5, &inbox_public_key(&[2u8; 32]), &sig).is_err());
        assert!(verify_inbox_key(&dk, conv, 5, &pk, &sig[..63]).is_err());
    }
}
