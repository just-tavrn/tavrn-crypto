// SPDX-License-Identifier: MPL-2.0
//! History backup of per-epoch content keys (ENCRYPTION.md §7).
//!
//! One blob per conversation: `version(1) || nonce(12) || AES-256-GCM(json)` under the backup key,
//! AAD `"tavrn backup v1\0" || conversation`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::keys::BackupKey;
use crate::util::{aes_decrypt, aes_encrypt, b64url_decode_array, b64url_encode, check_conversation, random_array};

/// Version byte of the backup blob.
pub const BACKUP_VERSION: u8 = 1;
/// AAD prefix of the backup blob (followed by the conversation id).
pub const BACKUP_AAD: &[u8] = b"tavrn backup v1\0";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupPlain {
    v: u8,
    conversation: String,
    /// Epoch (decimal string) → base64url content key.
    keys: BTreeMap<String, String>,
}

impl Drop for BackupPlain {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for v in self.keys.values_mut() {
            v.zeroize();
        }
    }
}

fn aad(conversation: &str) -> Vec<u8> {
    let mut aad = BACKUP_AAD.to_vec();
    aad.extend_from_slice(conversation.as_bytes());
    aad
}

/// Encrypts the epoch → content key map of one conversation.
pub fn encrypt_backup(key: &BackupKey, conversation: &str, keys: &BTreeMap<u64, [u8; 32]>) -> Result<Vec<u8>> {
    encrypt_backup_with_nonce(key, &random_array::<12>()?, conversation, keys)
}

/// [`encrypt_backup`] with a caller-chosen nonce (test vectors only).
pub(crate) fn encrypt_backup_with_nonce(
    key: &BackupKey,
    nonce: &[u8; 12],
    conversation: &str,
    keys: &BTreeMap<u64, [u8; 32]>,
) -> Result<Vec<u8>> {
    check_conversation(conversation)?;
    let plain = BackupPlain {
        v: BACKUP_VERSION,
        conversation: conversation.to_owned(),
        keys: keys.iter().map(|(e, k)| (e.to_string(), b64url_encode(k))).collect(),
    };
    let json = Zeroizing::new(serde_json::to_vec(&plain).map_err(|_| CryptoError::InvalidInput("backup"))?);
    let ciphertext = aes_encrypt(&key.0, nonce, &aad(conversation), &json)?;
    let mut out = Vec::with_capacity(13 + ciphertext.len());
    out.push(BACKUP_VERSION);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts a backup blob of `conversation`.
pub fn decrypt_backup(key: &BackupKey, conversation: &str, blob: &[u8]) -> Result<BTreeMap<u64, Zeroizing<[u8; 32]>>> {
    check_conversation(conversation)?;
    if blob.len() < 1 + 12 + 16 {
        return Err(CryptoError::InvalidInput("backup too short"));
    }
    if blob[0] != BACKUP_VERSION {
        return Err(CryptoError::UnsupportedVersion);
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[1..13]);
    let json = Zeroizing::new(aes_decrypt(&key.0, &nonce, &aad(conversation), &blob[13..])?);
    let plain: BackupPlain = serde_json::from_slice(&json).map_err(|_| CryptoError::InvalidInput("backup content"))?;
    if plain.v != BACKUP_VERSION {
        return Err(CryptoError::UnsupportedVersion);
    }
    if plain.conversation != conversation {
        return Err(CryptoError::WrongGroup);
    }
    let mut out = BTreeMap::new();
    for (epoch, k) in &plain.keys {
        let epoch: u64 = epoch.parse().map_err(|_| CryptoError::InvalidInput("backup epoch"))?;
        out.insert(epoch, Zeroizing::new(b64url_decode_array::<32>(k, "backup key")?));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    const CONV: &str = "node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V4X";

    fn keys() -> BTreeMap<u64, [u8; 32]> {
        BTreeMap::from([(0, [1u8; 32]), (5, [2u8; 32])])
    }

    #[test]
    fn roundtrip() {
        let k = BackupKey::from_bytes([9u8; 32]);
        let blob = encrypt_backup(&k, CONV, &keys()).expect("encrypt");
        let out = decrypt_backup(&k, CONV, &blob).expect("decrypt");
        assert_eq!(out.len(), 2);
        assert_eq!(*out[&5], [2u8; 32]);
        let empty = encrypt_backup(&k, CONV, &BTreeMap::new()).expect("encrypt");
        assert!(decrypt_backup(&k, CONV, &empty).expect("decrypt").is_empty());
    }

    #[test]
    fn wrong_key_conversation_or_tampering_fails() {
        let k = BackupKey::from_bytes([9u8; 32]);
        let blob = encrypt_backup(&k, CONV, &keys()).expect("encrypt");
        assert_eq!(
            decrypt_backup(&BackupKey::from_bytes([8u8; 32]), CONV, &blob).err(),
            Some(CryptoError::DecryptionFailed)
        );
        assert_eq!(
            decrypt_backup(&k, "node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V4Y", &blob).err(),
            Some(CryptoError::DecryptionFailed)
        );
        let mut bad = blob.clone();
        bad[20] ^= 1;
        assert_eq!(decrypt_backup(&k, CONV, &bad).err(), Some(CryptoError::DecryptionFailed));
        let mut v2 = blob;
        v2[0] = 2;
        assert_eq!(decrypt_backup(&k, CONV, &v2).err(), Some(CryptoError::UnsupportedVersion));
        assert!(decrypt_backup(&k, CONV, &[1, 2, 3]).is_err());
        assert!(decrypt_backup(&k, "bad", &[0u8; 64]).is_err());
    }
}
