// SPDX-License-Identifier: MPL-2.0
//! Identity key rotation with continuity (ENCRYPTION.md §2.1, §2.3, §9a).
//!
//! Generation 0 of an account's identity key is derived from the master secret (`keys`). A rotation keeps
//! the master secret and replaces the signing identity with a fresh random Ed25519 key:
//!
//! - the new key is wrapped for the home node as the `identity_blob`:
//!   `0x01 || nonce(12) || AES-256-GCM(identity_wrap_key, nonce, aad = user address, seed(32))` with
//!   `identity_wrap_key = HKDF-Expand(PRK, "tavrn identity wrap v1")`; any device holding the master secret
//!   unwraps it, the node never can;
//! - a **continuity statement** `{ old_key, new_key, at }` is signed by both keys over
//!   `"tavrn identity continuity v1" || JCS(statement)`, so contacts can follow the key from the pinned one
//!   to the new one without a warning.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::keys::{DeviceAttestation, MasterSecret, attest_device_with};
use crate::util::{aes_decrypt, aes_encrypt, b64url_decode_array, b64url_encode, check_user_address, random_array};

/// Version byte of an identity blob.
pub const IDENTITY_BLOB_VERSION: u8 = 1;
/// Length of an identity blob: version, nonce, 32-byte seed and 16-byte tag.
pub const IDENTITY_BLOB_LEN: usize = 1 + 12 + 32 + 16;
/// Domain separation prefix of the continuity signatures.
pub const CONTINUITY_CONTEXT: &[u8] = b"tavrn identity continuity v1";
/// Upper bound for the `at` field (an RFC 3339 time; the node checks the format and the clock).
const MAX_AT_LEN: usize = 64;
/// Longest chain that is followed (a hostile node cannot make clients verify unbounded chains; one rotation per
/// hour is allowed, so this covers decades).
pub const MAX_CHAIN: usize = 10_000;

/// An identity signing key of any generation: derived from the master secret (generation 0) or a rotated,
/// random one. Zeroized on drop.
pub struct IdentityKey(SigningKey);

impl std::fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IdentityKey(..)")
    }
}

impl IdentityKey {
    /// A fresh random identity key (a rotation).
    pub fn generate() -> Result<Self> {
        Ok(Self(SigningKey::from_bytes(&Zeroizing::new(random_array::<32>()?))))
    }

    /// Generation 0: the key derived from the master secret.
    pub fn from_master(master: &MasterSecret) -> Self {
        Self(master.identity_signing_key())
    }

    /// From the 32-byte Ed25519 seed (local secure storage).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// The 32-byte seed (local secure storage only).
    pub fn to_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    /// The public identity key the home node publishes.
    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// Attests a device key (ENCRYPTION.md §3.1) with this identity key.
    pub fn attest_device(
        &self,
        user_address: &str,
        device_id: &str,
        device_public_key: &[u8; 32],
    ) -> Result<DeviceAttestation> {
        attest_device_with(&self.0, user_address, device_id, device_public_key)
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }
}

/// Encrypts a rotated identity key for the home node (`identity_blob`).
pub fn wrap_identity_key(master: &MasterSecret, identity: &IdentityKey, user_address: &str) -> Result<Vec<u8>> {
    wrap_identity_with_nonce(master, identity, &random_array::<12>()?, user_address)
}

/// [`wrap_identity_key`] with a caller-chosen nonce (test vectors only).
pub(crate) fn wrap_identity_with_nonce(
    master: &MasterSecret,
    identity: &IdentityKey,
    nonce: &[u8; 12],
    user_address: &str,
) -> Result<Vec<u8>> {
    check_user_address(user_address)?;
    let key = master.identity_wrap_key();
    let ciphertext = aes_encrypt(&key, nonce, user_address.as_bytes(), identity.to_seed().as_slice())?;
    let mut out = Vec::with_capacity(IDENTITY_BLOB_LEN);
    out.push(IDENTITY_BLOB_VERSION);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts an identity blob. Fails with [`CryptoError::DecryptionFailed`] for another master secret or
/// account, or tampered bytes. Callers check that the key's public half is the published identity key.
pub fn unwrap_identity_key(master: &MasterSecret, blob: &[u8], user_address: &str) -> Result<IdentityKey> {
    check_user_address(user_address)?;
    if blob.len() != IDENTITY_BLOB_LEN {
        return Err(CryptoError::InvalidInput("identity blob length"));
    }
    if blob[0] != IDENTITY_BLOB_VERSION {
        return Err(CryptoError::UnsupportedVersion);
    }
    let nonce: [u8; 12] = blob[1..13].try_into().map_err(|_| CryptoError::InvalidInput("identity blob"))?;
    let seed = Zeroizing::new(aes_decrypt(&master.identity_wrap_key(), &nonce, user_address.as_bytes(), &blob[13..])?);
    let seed: Zeroizing<[u8; 32]> =
        Zeroizing::new(seed.as_slice().try_into().map_err(|_| CryptoError::DecryptionFailed)?);
    Ok(IdentityKey::from_seed(&seed))
}

/// A signed continuity statement (base64url keys and signatures, RFC 3339 time).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinuityStatement {
    pub old_key: String,
    pub new_key: String,
    pub at: String,
    pub sig_old: String,
    pub sig_new: String,
}

/// The signed bytes: `"tavrn identity continuity v1" || JCS({ "old_key", "new_key", "at" })`.
pub fn continuity_message(old_key: &str, new_key: &str, at: &str) -> Result<Vec<u8>> {
    if at.is_empty() || at.len() > MAX_AT_LEN {
        return Err(CryptoError::InvalidInput("continuity time"));
    }
    let canonical = serde_json_canonicalizer::to_string(&json!({ "old_key": old_key, "new_key": new_key, "at": at }))
        .map_err(|_| CryptoError::InvalidInput("continuity statement"))?;
    let mut msg = Vec::with_capacity(CONTINUITY_CONTEXT.len() + canonical.len());
    msg.extend_from_slice(CONTINUITY_CONTEXT);
    msg.extend_from_slice(canonical.as_bytes());
    Ok(msg)
}

/// Signs the statement "`old` is replaced by `new` at `at`" with both keys.
pub fn sign_continuity(old: &IdentityKey, new: &IdentityKey, at: &str) -> Result<ContinuityStatement> {
    let (old_key, new_key) = (b64url_encode(&old.public_key()), b64url_encode(&new.public_key()));
    if old_key == new_key {
        return Err(CryptoError::InvalidInput("continuity keys must differ"));
    }
    let msg = continuity_message(&old_key, &new_key, at)?;
    Ok(ContinuityStatement {
        sig_old: b64url_encode(&old.sign(&msg)),
        sig_new: b64url_encode(&new.sign(&msg)),
        old_key,
        new_key,
        at: at.to_owned(),
    })
}

fn verifying_key(b64: &str) -> Result<VerifyingKey> {
    let bytes = b64url_decode_array::<32>(b64, "identity key").map_err(|_| CryptoError::BadSignature)?;
    // Small-order (weak) keys are refused by `verify_strict`.
    VerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::BadSignature)
}

/// Checks both signatures of a statement (strict Ed25519, distinct non-weak keys).
pub fn verify_continuity(s: &ContinuityStatement) -> Result<()> {
    if s.old_key == s.new_key {
        return Err(CryptoError::BadSignature);
    }
    let msg = continuity_message(&s.old_key, &s.new_key, &s.at)?;
    for (key, sig) in [(&s.old_key, &s.sig_old), (&s.new_key, &s.sig_new)] {
        let signature = b64url_decode_array::<64>(sig, "signature").map_err(|_| CryptoError::BadSignature)?;
        verifying_key(key)?
            .verify_strict(&msg, &Signature::from_bytes(&signature))
            .map_err(|_| CryptoError::BadSignature)?;
    }
    Ok(())
}

/// Is `to` reachable from `from` through valid, consecutive statements of `chain` (oldest first)? `true`
/// for `from == to`. The walk starts at the first statement whose `old_key` is `from`.
pub fn continuity_reaches(chain: &[ContinuityStatement], from: &str, to: &str) -> bool {
    if from == to {
        return true;
    }
    if chain.len() > MAX_CHAIN {
        return false;
    }
    let Some(start) = chain.iter().position(|s| s.old_key == from) else { return false };
    let mut current = from;
    for s in &chain[start..] {
        if s.old_key != current || verify_continuity(s).is_err() {
            return false;
        }
        current = &s.new_key;
        if current == to {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::keys::verify_device_attestation;

    const ALICE: &str = "alice@node.example";
    const DEV: &str = "01J9ZK3G5M8Q2W4E6R8T0Y2V4X";
    const AT: &str = "2026-10-06T12:00:00Z";

    fn master() -> MasterSecret {
        MasterSecret::from_bytes([42u8; 32])
    }

    #[test]
    fn generation_zero_is_the_derived_key() {
        let m = master();
        assert_eq!(IdentityKey::from_master(&m).public_key(), m.identity_public_key());
        let rotated = IdentityKey::generate().expect("rng");
        assert_ne!(rotated.public_key(), m.identity_public_key());
        let back = IdentityKey::from_seed(&rotated.to_seed());
        assert_eq!(back.public_key(), rotated.public_key());
        assert_eq!(format!("{rotated:?}"), "IdentityKey(..)");
    }

    #[test]
    fn rotated_key_attests_devices() {
        let rotated = IdentityKey::generate().expect("rng");
        let device = SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes();
        let att = rotated.attest_device(ALICE, DEV, &device).expect("attest");
        verify_device_attestation(&att, &rotated.public_key()).expect("verify");
        assert!(verify_device_attestation(&att, &master().identity_public_key()).is_err());
    }

    #[test]
    fn blob_roundtrip_and_binding() {
        let m = master();
        let rotated = IdentityKey::generate().expect("rng");
        let blob = wrap_identity_key(&m, &rotated, ALICE).expect("wrap");
        assert_eq!(blob.len(), IDENTITY_BLOB_LEN);
        assert_eq!(unwrap_identity_key(&m, &blob, ALICE).expect("unwrap").public_key(), rotated.public_key());
        // Another master secret, another account, tampering, another version or length: refused.
        assert_eq!(
            unwrap_identity_key(&MasterSecret::from_bytes([1u8; 32]), &blob, ALICE).err(),
            Some(CryptoError::DecryptionFailed)
        );
        assert_eq!(unwrap_identity_key(&m, &blob, "bob@node.example").err(), Some(CryptoError::DecryptionFailed));
        let mut bad = blob.clone();
        bad[20] ^= 1;
        assert_eq!(unwrap_identity_key(&m, &bad, ALICE).err(), Some(CryptoError::DecryptionFailed));
        let mut v2 = blob.clone();
        v2[0] = 2;
        assert_eq!(unwrap_identity_key(&m, &v2, ALICE).err(), Some(CryptoError::UnsupportedVersion));
        assert!(unwrap_identity_key(&m, &blob[..60], ALICE).is_err());
        assert!(wrap_identity_key(&m, &rotated, "no address").is_err());
        // The wrap key is separated from the other derived keys.
        assert_ne!(*m.identity_wrap_key(), *m.backup_key().to_bytes());
    }

    #[test]
    fn continuity_signs_and_verifies() {
        let old = IdentityKey::from_master(&master());
        let new = IdentityKey::generate().expect("rng");
        let s = sign_continuity(&old, &new, AT).expect("sign");
        verify_continuity(&s).expect("valid");
        assert_eq!(s.old_key, b64url_encode(&old.public_key()));

        let mut t = s.clone();
        t.at = "2026-10-06T12:00:01Z".into();
        assert_eq!(verify_continuity(&t), Err(CryptoError::BadSignature), "time is signed");
        let mut t = s.clone();
        std::mem::swap(&mut t.sig_old, &mut t.sig_new);
        assert_eq!(verify_continuity(&t), Err(CryptoError::BadSignature), "each key signs");
        // Signed by the new key only (a statement a thief of the new key alone could make).
        let mallory = IdentityKey::generate().expect("rng");
        let forged = sign_continuity(&mallory, &new, AT).expect("sign");
        let mut t = s.clone();
        t.sig_old = forged.sig_old;
        assert_eq!(verify_continuity(&t), Err(CryptoError::BadSignature));
        let mut t = s.clone();
        t.new_key = t.old_key.clone();
        assert_eq!(verify_continuity(&t), Err(CryptoError::BadSignature));
        let mut t = s;
        t.sig_new = "AAAA".into();
        assert_eq!(verify_continuity(&t), Err(CryptoError::BadSignature));
        assert!(sign_continuity(&old, &old, AT).is_err());
        assert!(sign_continuity(&old, &new, "").is_err());
    }

    #[test]
    fn message_layout_is_context_and_jcs() {
        let msg = continuity_message("b", "c", "a").expect("msg");
        assert_eq!(msg, b"tavrn identity continuity v1{\"at\":\"a\",\"new_key\":\"c\",\"old_key\":\"b\"}".to_vec());
    }

    #[test]
    fn chains_are_followed_in_order() {
        let k0 = IdentityKey::from_master(&master());
        let k1 = IdentityKey::generate().expect("rng");
        let k2 = IdentityKey::generate().expect("rng");
        let k3 = IdentityKey::generate().expect("rng");
        let pk = |k: &IdentityKey| b64url_encode(&k.public_key());
        let chain = vec![
            sign_continuity(&k0, &k1, AT).expect("s"),
            sign_continuity(&k1, &k2, AT).expect("s"),
            sign_continuity(&k2, &k3, AT).expect("s"),
        ];
        assert!(continuity_reaches(&chain, &pk(&k0), &pk(&k3)));
        assert!(continuity_reaches(&chain, &pk(&k1), &pk(&k3)));
        assert!(continuity_reaches(&chain, &pk(&k2), &pk(&k2)));
        assert!(!continuity_reaches(&chain, &pk(&k3), &pk(&k0)), "never backwards");
        assert!(!continuity_reaches(&[], &pk(&k0), &pk(&k1)));
        // A gap or an invalid link breaks the chain.
        assert!(!continuity_reaches(&[chain[0].clone(), chain[2].clone()], &pk(&k0), &pk(&k3)));
        let mut broken = chain.clone();
        broken[1].sig_new = broken[0].sig_new.clone();
        assert!(!continuity_reaches(&broken, &pk(&k0), &pk(&k3)));
        assert!(continuity_reaches(&broken, &pk(&k2), &pk(&k3)), "later links stand alone");
    }

    #[test]
    fn continuity_refuses_small_order_keys() {
        // The identity point: verify_strict refuses small-order keys whatever the signature.
        let mut weak = [0u8; 32];
        weak[0] = 1;
        let k1 = IdentityKey::generate().expect("rng");
        let s = ContinuityStatement {
            old_key: b64url_encode(&weak),
            new_key: b64url_encode(&k1.public_key()),
            at: AT.to_owned(),
            sig_old: b64url_encode(&[0u8; 64]),
            sig_new: b64url_encode(&[0u8; 64]),
        };
        assert_eq!(verify_continuity(&s), Err(CryptoError::BadSignature));
    }
}
