// SPDX-License-Identifier: MPL-2.0
//! Encrypted message content (ENCRYPTION.md §5).
//!
//! `content = base64url( version(1) || epoch(8, BE) || nonce(12) || AES-256-GCM(ciphertext || tag) )`
//! with plaintext `device_signature(64) || json` and AAD from [`content_aad`].

use ed25519_dalek::{Signature, VerifyingKey};
use zeroize::Zeroizing;

use crate::device::Device;
use crate::error::{CryptoError, Result};
use crate::util::{aes_decrypt, aes_encrypt, b64url_decode, b64url_encode, put_str16, random_array};

/// Version byte of the content envelope.
pub const CONTENT_VERSION: u8 = 1;
/// MLS exporter label of the per-epoch content key.
pub const CONTENT_EXPORTER_LABEL: &str = "tavrn content v1";
/// MLS exporter label of the per-epoch voice frame key (ENCRYPTION.md §5a).
pub const VOICE_EXPORTER_LABEL: &str = "tavrn voice frame v1";
/// Domain separation prefix of the device signature over content.
pub const CONTENT_SIGNATURE_CONTEXT: &[u8] = b"tavrn content signature v1\0";

const HEADER_LEN: usize = 1 + 8 + 12;
const MIN_LEN: usize = HEADER_LEN + 64 + 16;

/// Canonical AAD: `version(1) || u16 len || conversation || epoch(8, BE) || u16 len || author ||
/// u16 len || device_id`.
pub fn content_aad(conversation: &str, epoch: u64, author: &str, device_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + 8 + 6 + conversation.len() + author.len() + device_id.len());
    aad.push(CONTENT_VERSION);
    put_str16(&mut aad, conversation);
    aad.extend_from_slice(&epoch.to_be_bytes());
    put_str16(&mut aad, author);
    put_str16(&mut aad, device_id);
    aad
}

fn signed_bytes(aad: &[u8], nonce: &[u8; 12], json: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(CONTENT_SIGNATURE_CONTEXT.len() + aad.len() + 12 + json.len());
    msg.extend_from_slice(CONTENT_SIGNATURE_CONTEXT);
    msg.extend_from_slice(aad);
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(json);
    msg
}

fn check_json_object(json: &str) -> Result<()> {
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(serde_json::Value::Object(_)) => Ok(()),
        _ => Err(CryptoError::InvalidInput("content must be a JSON object")),
    }
}

/// Encrypts and signs `json` with the content key of `epoch`. Returns the base64url envelope.
pub(crate) fn seal(key: &[u8; 32], conversation: &str, epoch: u64, device: &Device, json: &str) -> Result<String> {
    seal_with_nonce(key, &random_array::<12>()?, conversation, epoch, device, json)
}

/// [`seal`] with a caller-chosen nonce (test vectors only; nonces must never repeat).
pub(crate) fn seal_with_nonce(
    key: &[u8; 32],
    nonce: &[u8; 12],
    conversation: &str,
    epoch: u64,
    device: &Device,
    json: &str,
) -> Result<String> {
    check_json_object(json)?;
    let nonce = *nonce;
    let aad = content_aad(conversation, epoch, device.user_address(), device.device_id());
    let signature = device.sign_raw(&signed_bytes(&aad, &nonce, json.as_bytes()));
    let mut plaintext = Zeroizing::new(Vec::with_capacity(64 + json.len()));
    plaintext.extend_from_slice(&signature);
    plaintext.extend_from_slice(json.as_bytes());
    let ciphertext = aes_encrypt(key, &nonce, &aad, &plaintext)?;
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.push(CONTENT_VERSION);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(b64url_encode(&out))
}

/// Plaintext header of an envelope: what the node can read without keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentHeader {
    /// Envelope version (currently 1).
    pub version: u8,
    /// MLS epoch whose content key encrypted the message.
    pub epoch: u64,
    /// AES-GCM nonce; clients treat a repeated `(epoch, nonce)` as a replay.
    pub nonce: [u8; 12],
}

/// Parses the plaintext header of a base64url envelope (usable by the node to check `epoch`).
pub fn content_header(content: &str) -> Result<ContentHeader> {
    let bytes = b64url_decode(content)?;
    parse(&bytes).map(|(h, _)| h)
}

fn parse(bytes: &[u8]) -> Result<(ContentHeader, &[u8])> {
    if bytes.len() < MIN_LEN {
        return Err(CryptoError::InvalidInput("content too short"));
    }
    let (header, ciphertext) = bytes.split_at(HEADER_LEN);
    if header[0] != CONTENT_VERSION {
        return Err(CryptoError::UnsupportedVersion);
    }
    let mut epoch = [0u8; 8];
    epoch.copy_from_slice(&header[1..9]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&header[9..21]);
    Ok((ContentHeader { version: header[0], epoch: u64::from_be_bytes(epoch), nonce }, ciphertext))
}

/// Decrypts an envelope with `key` and verifies the device signature with `device_public_key`.
pub(crate) fn open(
    key: &[u8; 32],
    conversation: &str,
    author: &str,
    device_id: &str,
    device_public_key: &[u8; 32],
    header: &ContentHeader,
    ciphertext: &[u8],
) -> Result<String> {
    let aad = content_aad(conversation, header.epoch, author, device_id);
    let plaintext = Zeroizing::new(aes_decrypt(key, &header.nonce, &aad, ciphertext)?);
    if plaintext.len() < 64 {
        return Err(CryptoError::DecryptionFailed);
    }
    let (sig, json) = plaintext.split_at(64);
    let sig = Signature::from_slice(sig).map_err(|_| CryptoError::BadSignature)?;
    let vk = VerifyingKey::from_bytes(device_public_key).map_err(|_| CryptoError::BadSignature)?;
    vk.verify_strict(&signed_bytes(&aad, &header.nonce, json), &sig).map_err(|_| CryptoError::BadSignature)?;
    let json = std::str::from_utf8(json).map_err(|_| CryptoError::InvalidInput("content is not UTF-8"))?;
    check_json_object(json)?;
    Ok(json.to_owned())
}

/// Splits a base64url envelope into header and ciphertext.
pub(crate) fn decode(content: &str) -> Result<(ContentHeader, Vec<u8>)> {
    let bytes = b64url_decode(content)?;
    let (header, ciphertext) = parse(&bytes)?;
    Ok((header, ciphertext.to_vec()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    const CONV: &str = "node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V4X";
    const DEV: &str = "01J9ZK3G5M8Q2W4E6R8T0Y2V4Y";
    const JSON: &str = r#"{"type":"text","body":"hi"}"#;

    fn device() -> Device {
        Device::from_secret("alice@node.example", DEV, &[3u8; 32]).expect("device")
    }

    fn roundtrip(content: &str, key: &[u8; 32], author: &str, device_id: &str, pk: &[u8; 32]) -> Result<String> {
        let (h, ct) = decode(content)?;
        open(key, CONV, author, device_id, pk, &h, &ct)
    }

    #[test]
    fn seal_open_roundtrip() {
        let d = device();
        let key = [5u8; 32];
        let c = seal(&key, CONV, 7, &d, JSON).expect("seal");
        let h = content_header(&c).expect("header");
        assert_eq!((h.version, h.epoch), (1, 7));
        assert_eq!(roundtrip(&c, &key, "alice@node.example", DEV, &d.public_key()).ok().as_deref(), Some(JSON));
    }

    #[test]
    fn nonces_are_fresh() {
        let d = device();
        let a = seal(&[5u8; 32], CONV, 7, &d, JSON).expect("seal");
        let b = seal(&[5u8; 32], CONV, 7, &d, JSON).expect("seal");
        assert_ne!(content_header(&a).expect("h").nonce, content_header(&b).expect("h").nonce);
    }

    #[test]
    fn context_mismatches_fail() {
        let d = device();
        let key = [5u8; 32];
        let pk = d.public_key();
        let c = seal(&key, CONV, 7, &d, JSON).expect("seal");
        assert_eq!(roundtrip(&c, &[6u8; 32], "alice@node.example", DEV, &pk), Err(CryptoError::DecryptionFailed));
        assert_eq!(roundtrip(&c, &key, "bob@node.example", DEV, &pk), Err(CryptoError::DecryptionFailed));
        assert_eq!(
            roundtrip(&c, &key, "alice@node.example", "01J9ZK3G5M8Q2W4E6R8T0Y2V4Z", &pk),
            Err(CryptoError::DecryptionFailed)
        );
        let (h, ct) = decode(&c).expect("decode");
        assert_eq!(
            open(&key, "node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V4Z", "alice@node.example", DEV, &pk, &h, &ct),
            Err(CryptoError::DecryptionFailed)
        );
        // Wrong epoch in the header (the node rewrote it).
        let mut bytes = b64url_decode(&c).expect("b64");
        bytes[8] ^= 1;
        assert_eq!(
            roundtrip(&b64url_encode(&bytes), &key, "alice@node.example", DEV, &pk),
            Err(CryptoError::DecryptionFailed)
        );
    }

    #[test]
    fn signature_by_other_device_fails() {
        // A member who knows the epoch key cannot impersonate another device.
        let d = device();
        let key = [5u8; 32];
        let c = seal(&key, CONV, 7, &d, JSON).expect("seal");
        let other = Device::from_secret("alice@node.example", DEV, &[4u8; 32]).expect("device");
        assert_eq!(roundtrip(&c, &key, "alice@node.example", DEV, &other.public_key()), Err(CryptoError::BadSignature));
    }

    #[test]
    fn tampering_and_garbage_fail() {
        let d = device();
        let key = [5u8; 32];
        let c = seal(&key, CONV, 7, &d, JSON).expect("seal");
        let mut bytes = b64url_decode(&c).expect("b64");
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert_eq!(
            roundtrip(&b64url_encode(&bytes), &key, "alice@node.example", DEV, &d.public_key()),
            Err(CryptoError::DecryptionFailed)
        );
        bytes[0] = 2;
        assert_eq!(content_header(&b64url_encode(&bytes)), Err(CryptoError::UnsupportedVersion));
        assert!(content_header("").is_err());
        assert!(content_header("!!!").is_err());
        assert!(content_header(&b64url_encode(&[1u8; 50])).is_err());
    }

    #[test]
    fn only_json_objects_are_sealed() {
        let d = device();
        assert!(seal(&[5u8; 32], CONV, 7, &d, "not json").is_err());
        assert!(seal(&[5u8; 32], CONV, 7, &d, "[1,2]").is_err());
    }

    #[test]
    fn aad_is_length_prefixed() {
        // Moving bytes between fields must change the AAD.
        assert_ne!(content_aad("a/b", 1, "cd@e", "f"), content_aad("a/bc", 1, "d@e", "f"));
    }
}
