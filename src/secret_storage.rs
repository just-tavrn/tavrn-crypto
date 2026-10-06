// SPDX-License-Identifier: MPL-2.0
//! Secret storage (ENCRYPTION.md §2.4): the master secret wrapped for the user's home node.
//!
//! The node stores one entry per unlock method and hands entries out only to fully authenticated
//! sessions (password and second factor). It can never unwrap them:
//!
//! - `recovery`: wrapping key derived from the [`RecoveryKey`](crate::RecoveryKey), which only the
//!   user holds;
//! - `passkey:<credential id>`: wrapping key derived from the output of the WebAuthn PRF extension
//!   of that credential, evaluated with [`PRF_INPUT`].
//!
//! Entry format: `0x01 || nonce(12) || AES-256-GCM(wrapping key, nonce, aad, master secret)`,
//! `aad = "tavrn secret storage v1" || 0x00 || str16(user address) || str16(method)`.

use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::keys::{MasterSecret, hkdf_no_salt};
use crate::util::{aes_decrypt, aes_encrypt, check_user_address, put_str16, random_array};

/// Version byte of a wrapped master secret.
pub const WRAPPED_VERSION: u8 = 1;
/// Length of a wrapped master secret: version, nonce, 32-byte secret and 16-byte tag.
pub const WRAPPED_LEN: usize = 1 + 12 + 32 + 16;
/// AAD prefix (followed by the user address and the method label).
pub const SECRET_STORAGE_AAD: &[u8] = b"tavrn secret storage v1\0";
/// Method label of the recovery key entry.
pub const METHOD_RECOVERY: &str = "recovery";
/// Prefix of a passkey method label; followed by the base64url WebAuthn credential id.
pub const METHOD_PASSKEY_PREFIX: &str = "passkey:";
/// HKDF info of the wrapping key derived from a WebAuthn PRF output.
pub const PASSKEY_WRAP_INFO: &[u8] = b"tavrn secret storage passkey v1";
/// Input (`prf.eval.first`) that clients pass to the WebAuthn PRF extension. The same input is
/// used for every credential: the PRF output is specific to the credential and the relying party.
pub const PRF_INPUT: &[u8] = b"tavrn secret storage prf v1";
/// Upper bound for a credential id in a method label (WebAuthn allows 1023 bytes, base64url).
const MAX_CREDENTIAL_ID_CHARS: usize = 1364;

/// `passkey:<credential id>` for a base64url credential id.
pub fn passkey_method(credential_id: &str) -> Result<String> {
    let method = format!("{METHOD_PASSKEY_PREFIX}{credential_id}");
    check_method(&method)?;
    Ok(method)
}

/// `true` for `recovery` and `passkey:<base64url credential id>`.
pub fn valid_method(method: &str) -> bool {
    if method == METHOD_RECOVERY {
        return true;
    }
    method.strip_prefix(METHOD_PASSKEY_PREFIX).is_some_and(|id| {
        !id.is_empty()
            && id.len() <= MAX_CREDENTIAL_ID_CHARS
            && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    })
}

fn check_method(method: &str) -> Result<()> {
    valid_method(method).then_some(()).ok_or(CryptoError::InvalidInput("secret storage method"))
}

/// The additional authenticated data that binds an entry to its account and method.
pub fn secret_storage_aad(user_address: &str, method: &str) -> Result<Vec<u8>> {
    check_user_address(user_address)?;
    check_method(method)?;
    let mut aad = Vec::with_capacity(SECRET_STORAGE_AAD.len() + 4 + user_address.len() + method.len());
    aad.extend_from_slice(SECRET_STORAGE_AAD);
    put_str16(&mut aad, user_address);
    put_str16(&mut aad, method);
    Ok(aad)
}

/// Wrapping key from the 32-byte output of the WebAuthn PRF extension:
/// `HKDF-SHA256(salt = none, IKM = prf output, info = "tavrn secret storage passkey v1")`.
pub fn passkey_wrapping_key(prf_output: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if prf_output.len() != 32 {
        return Err(CryptoError::InvalidInput("prf output must be 32 bytes"));
    }
    Ok(hkdf_no_salt(prf_output, PASSKEY_WRAP_INFO))
}

/// Encrypts the master secret for one unlock method.
pub fn wrap_master_secret(
    master: &MasterSecret,
    wrapping_key: &[u8; 32],
    user_address: &str,
    method: &str,
) -> Result<Vec<u8>> {
    wrap_with_nonce(master, wrapping_key, &random_array::<12>()?, user_address, method)
}

/// [`wrap_master_secret`] with a caller-chosen nonce (test vectors only).
pub(crate) fn wrap_with_nonce(
    master: &MasterSecret,
    wrapping_key: &[u8; 32],
    nonce: &[u8; 12],
    user_address: &str,
    method: &str,
) -> Result<Vec<u8>> {
    let aad = secret_storage_aad(user_address, method)?;
    let ciphertext = aes_encrypt(wrapping_key, nonce, &aad, master.to_bytes().as_slice())?;
    let mut out = Vec::with_capacity(WRAPPED_LEN);
    out.push(WRAPPED_VERSION);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts an entry. Fails with [`CryptoError::DecryptionFailed`] for a wrong key, another
/// account or method, or tampered bytes.
pub fn unwrap_master_secret(
    wrapped: &[u8],
    wrapping_key: &[u8; 32],
    user_address: &str,
    method: &str,
) -> Result<MasterSecret> {
    let aad = secret_storage_aad(user_address, method)?;
    if wrapped.len() != WRAPPED_LEN {
        return Err(CryptoError::InvalidInput("wrapped master secret length"));
    }
    if wrapped[0] != WRAPPED_VERSION {
        return Err(CryptoError::UnsupportedVersion);
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&wrapped[1..13]);
    let plain = Zeroizing::new(aes_decrypt(wrapping_key, &nonce, &aad, &wrapped[13..])?);
    let bytes: [u8; 32] = plain.as_slice().try_into().map_err(|_| CryptoError::DecryptionFailed)?;
    Ok(MasterSecret::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::keys::RecoveryKey;

    const ALICE: &str = "alice@node.example";
    const CRED: &str = "AbC-_09";

    fn master() -> MasterSecret {
        MasterSecret::from_bytes([42u8; 32])
    }

    #[test]
    fn recovery_roundtrip() {
        let rk = RecoveryKey::generate().expect("rng");
        let wrapped = wrap_master_secret(&master(), &rk.wrapping_key(), ALICE, METHOD_RECOVERY).expect("wrap");
        assert_eq!(wrapped.len(), WRAPPED_LEN);
        assert_eq!(wrapped[0], WRAPPED_VERSION);
        let again = wrap_master_secret(&master(), &rk.wrapping_key(), ALICE, METHOD_RECOVERY).expect("wrap");
        assert_ne!(wrapped, again, "fresh nonce per wrap");
        // A recovery key typed back from its words unlocks the entry.
        let typed = RecoveryKey::from_text(&rk.to_words().expect("words")).expect("parse");
        let out = unwrap_master_secret(&wrapped, &typed.wrapping_key(), ALICE, METHOD_RECOVERY).expect("unwrap");
        assert_eq!(*out.to_bytes(), [42u8; 32]);
    }

    #[test]
    fn passkey_roundtrip() {
        let method = passkey_method(CRED).expect("method");
        assert_eq!(method, "passkey:AbC-_09");
        let key = passkey_wrapping_key(&[3u8; 32]).expect("key");
        let wrapped = wrap_master_secret(&master(), &key, ALICE, &method).expect("wrap");
        let out = unwrap_master_secret(&wrapped, &key, ALICE, &method).expect("unwrap");
        assert_eq!(*out.to_bytes(), [42u8; 32]);
        assert_ne!(*key, *passkey_wrapping_key(&[4u8; 32]).expect("key"));
        assert!(passkey_wrapping_key(&[3u8; 31]).is_err());
        assert!(passkey_wrapping_key(&[]).is_err());
    }

    #[test]
    fn wrong_key_account_method_or_tampering_fail() {
        let key = RecoveryKey::from_bytes([1u8; 32]).wrapping_key();
        let wrapped = wrap_master_secret(&master(), &key, ALICE, METHOD_RECOVERY).expect("wrap");
        let other = RecoveryKey::from_bytes([2u8; 32]).wrapping_key();
        assert_eq!(
            unwrap_master_secret(&wrapped, &other, ALICE, METHOD_RECOVERY).err(),
            Some(CryptoError::DecryptionFailed)
        );
        // A malicious node cannot move an entry to another account or method.
        assert_eq!(
            unwrap_master_secret(&wrapped, &key, "bob@node.example", METHOD_RECOVERY).err(),
            Some(CryptoError::DecryptionFailed)
        );
        let as_passkey = passkey_method(CRED).expect("method");
        assert_eq!(unwrap_master_secret(&wrapped, &key, ALICE, &as_passkey).err(), Some(CryptoError::DecryptionFailed));
        let mut bad = wrapped.clone();
        bad[20] ^= 1;
        assert_eq!(unwrap_master_secret(&bad, &key, ALICE, METHOD_RECOVERY).err(), Some(CryptoError::DecryptionFailed));
        let mut v2 = wrapped.clone();
        v2[0] = 2;
        assert_eq!(
            unwrap_master_secret(&v2, &key, ALICE, METHOD_RECOVERY).err(),
            Some(CryptoError::UnsupportedVersion)
        );
        assert!(unwrap_master_secret(&wrapped[..60], &key, ALICE, METHOD_RECOVERY).is_err());
        assert!(unwrap_master_secret(&[], &key, ALICE, METHOD_RECOVERY).is_err());
    }

    #[test]
    fn master_key_file_words_do_not_unlock_a_recovery_entry() {
        // Users may confuse the two; the word list decodes but the wrapping key differs.
        let rk = RecoveryKey::from_bytes([9u8; 32]);
        let wrapped = wrap_master_secret(&master(), &rk.wrapping_key(), ALICE, METHOD_RECOVERY).expect("wrap");
        let master_words = master().to_key_file(ALICE).expect("file");
        let words = master_words.lines().find_map(|l| l.strip_prefix("words: ")).expect("words");
        let confused = RecoveryKey::from_text(words).expect("words parse as any 32 bytes");
        assert_eq!(
            unwrap_master_secret(&wrapped, &confused.wrapping_key(), ALICE, METHOD_RECOVERY).err(),
            Some(CryptoError::DecryptionFailed)
        );
    }

    #[test]
    fn methods_and_addresses_are_validated() {
        assert!(valid_method("recovery"));
        assert!(valid_method("passkey:abc"));
        for bad in ["", "password", "passkey:", "passkey:a b", "passkey:a/b", "passkey:a=", "Recovery", "recovery "] {
            assert!(!valid_method(bad), "{bad}");
        }
        assert!(!valid_method(&format!("passkey:{}", "a".repeat(1365))));
        assert!(passkey_method("x/y").is_err());
        let key = [0u8; 32];
        assert!(wrap_master_secret(&master(), &key, "alice", METHOD_RECOVERY).is_err());
        assert!(wrap_master_secret(&master(), &key, ALICE, "password").is_err());
        assert!(secret_storage_aad(ALICE, "nope").is_err());
    }

    #[test]
    fn aad_layout() {
        let aad = secret_storage_aad(ALICE, METHOD_RECOVERY).expect("aad");
        let mut expected = b"tavrn secret storage v1\0".to_vec();
        expected.extend_from_slice(&[0, 18]);
        expected.extend_from_slice(ALICE.as_bytes());
        expected.extend_from_slice(&[0, 8]);
        expected.extend_from_slice(b"recovery");
        assert_eq!(aad, expected);
    }
}
