// SPDX-License-Identifier: MPL-2.0
//! Encrypted attachments (ENCRYPTION.md §6): one-shot AES-256-GCM with a random key per file.

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CryptoError, Result};
use crate::util::{aes_decrypt, aes_encrypt, random_array};

/// AAD of every attachment ciphertext.
pub const FILE_AAD: &[u8] = b"tavrn file v1";

/// Result of [`encrypt_file`]. `key`, `nonce` and `sha256` go into the encrypted message content.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EncryptedFile {
    /// Ciphertext including the 16-byte tag; this is what gets uploaded.
    pub ciphertext: Vec<u8>,
    /// Random 32-byte file key.
    pub key: [u8; 32],
    /// Random 12-byte nonce.
    pub nonce: [u8; 12],
    /// SHA-256 of `ciphertext` (the node's blob hash).
    pub sha256: [u8; 32],
}

/// Encrypts a file with a fresh random key and nonce.
pub fn encrypt_file(plaintext: &[u8]) -> Result<EncryptedFile> {
    encrypt_file_with(random_array::<32>()?, random_array::<12>()?, plaintext)
}

/// [`encrypt_file`] with caller-chosen key and nonce (test vectors only).
pub(crate) fn encrypt_file_with(key: [u8; 32], nonce: [u8; 12], plaintext: &[u8]) -> Result<EncryptedFile> {
    let ciphertext = aes_encrypt(&key, &nonce, FILE_AAD, plaintext)?;
    let sha256 = Sha256::digest(&ciphertext).into();
    Ok(EncryptedFile { ciphertext, key, nonce, sha256 })
}

/// Checks the ciphertext hash, then decrypts.
pub fn decrypt_file(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 12], sha256: &[u8; 32]) -> Result<Vec<u8>> {
    let actual: [u8; 32] = Sha256::digest(ciphertext).into();
    if &actual != sha256 {
        return Err(CryptoError::DecryptionFailed);
    }
    aes_decrypt(key, nonce, FILE_AAD, ciphertext)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn roundtrip() {
        let f = encrypt_file(b"picture bytes").expect("encrypt");
        assert_eq!(f.ciphertext.len(), 13 + 16);
        assert_eq!(decrypt_file(&f.ciphertext, &f.key, &f.nonce, &f.sha256).ok(), Some(b"picture bytes".to_vec()));
        let empty = encrypt_file(b"").expect("encrypt");
        assert_eq!(decrypt_file(&empty.ciphertext, &empty.key, &empty.nonce, &empty.sha256).ok(), Some(vec![]));
    }

    #[test]
    fn fresh_keys_per_file() {
        let a = encrypt_file(b"x").expect("encrypt");
        let b = encrypt_file(b"x").expect("encrypt");
        assert_ne!(a.key, b.key);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn rejects_swapped_or_tampered_blobs() {
        let f = encrypt_file(b"secret").expect("encrypt");
        let g = encrypt_file(b"other").expect("encrypt");
        assert_eq!(decrypt_file(&g.ciphertext, &f.key, &f.nonce, &f.sha256), Err(CryptoError::DecryptionFailed));
        let mut bad = f.ciphertext.clone();
        bad[0] ^= 1;
        assert_eq!(decrypt_file(&bad, &f.key, &f.nonce, &f.sha256), Err(CryptoError::DecryptionFailed));
        // Matching hash but wrong key.
        assert_eq!(decrypt_file(&f.ciphertext, &g.key, &f.nonce, &f.sha256), Err(CryptoError::DecryptionFailed));
        assert_eq!(decrypt_file(&[], &f.key, &f.nonce, &f.sha256), Err(CryptoError::DecryptionFailed));
    }
}
