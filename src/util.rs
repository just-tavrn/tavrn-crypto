// SPDX-License-Identifier: MPL-2.0
//! Small helpers: identifier validation, base64url, randomness, AES-256-GCM and a bounded binary
//! reader/writer for the crate's own serialization formats.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore};

use crate::error::{CryptoError, Result};

// ---- Identifiers ------------------------------------------------------------------------------

/// `username`: 2–32 characters of `[a-z0-9_.-]`, starting with a letter or digit (PROTOCOL.md §1).
pub fn valid_username(s: &str) -> bool {
    (2..=32).contains(&s.len())
        && s.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-'))
}

/// Node domain: lowercase DNS name without scheme, port or path (PROTOCOL.md §1).
pub fn valid_domain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

/// User address `<username>@<domain>`.
pub fn valid_user_address(s: &str) -> bool {
    match s.split_once('@') {
        Some((user, domain)) => valid_username(user) && valid_domain(domain),
        None => false,
    }
}

/// ULID: 26 characters of upper-case Crockford base32, first character `0`–`7`.
pub fn valid_ulid(s: &str) -> bool {
    s.len() == 26
        && s.as_bytes().first().is_some_and(|c| (b'0'..=b'7').contains(c))
        && s.bytes().all(|c| c.is_ascii_digit() || (c.is_ascii_uppercase() && !matches!(c, b'I' | b'L' | b'O' | b'U')))
}

/// Conversation reference `<node domain>/<conversation ULID>`; also the MLS group id.
pub fn valid_conversation(s: &str) -> bool {
    match s.split_once('/') {
        Some((domain, id)) => valid_domain(domain) && valid_ulid(id),
        None => false,
    }
}

/// Device identity `<username>@<domain>/<device ULID>` (identity of the MLS basic credential).
pub fn parse_device_identity(s: &str) -> Option<(&str, &str)> {
    let (address, device_id) = s.split_once('/')?;
    (valid_user_address(address) && valid_ulid(device_id)).then_some((address, device_id))
}

pub(crate) fn check_user_address(s: &str) -> Result<()> {
    valid_user_address(s).then_some(()).ok_or(CryptoError::InvalidInput("user address"))
}

pub(crate) fn check_device_id(s: &str) -> Result<()> {
    valid_ulid(s).then_some(()).ok_or(CryptoError::InvalidInput("device id"))
}

pub(crate) fn check_conversation(s: &str) -> Result<()> {
    valid_conversation(s).then_some(()).ok_or(CryptoError::InvalidInput("conversation id"))
}

// ---- Encoding ---------------------------------------------------------------------------------

/// base64url without padding (RFC 4648 §5), the encoding used everywhere in the protocol.
pub fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Strict base64url decoding (no padding, no whitespace).
pub fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).map_err(|_| CryptoError::InvalidInput("base64url"))
}

/// Decodes base64url into a fixed-size array.
pub(crate) fn b64url_decode_array<const N: usize>(s: &str, what: &'static str) -> Result<[u8; N]> {
    let v = b64url_decode(s).map_err(|_| CryptoError::InvalidInput(what))?;
    v.try_into().map_err(|_| CryptoError::InvalidInput(what))
}

// ---- Randomness and AEAD ----------------------------------------------------------------------

/// Fills an array from the operating system RNG (`crypto.getRandomValues` in browsers).
pub(crate) fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    OsRng.try_fill_bytes(&mut out).map_err(|_| CryptoError::Rng)?;
    Ok(out)
}

pub(crate) fn aes_encrypt(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::InvalidInput("plaintext too large"))
}

pub(crate) fn aes_decrypt(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError::DecryptionFailed)
}

// ---- Bounded binary encoding --------------------------------------------------------------------

/// Appends `len(u16 BE) || bytes`. Callers only pass validated identifiers (≤ 300 bytes).
pub(crate) fn put_str16(out: &mut Vec<u8>, s: &str) {
    let len = u16::try_from(s.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&s.as_bytes()[..usize::from(len)]);
}

/// Appends `len(u32 BE) || bytes`.
pub(crate) fn put_bytes32(out: &mut Vec<u8>, b: &[u8]) -> Result<()> {
    let len = u32::try_from(b.len()).map_err(|_| CryptoError::InvalidInput("value too large"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

/// Reader over untrusted bytes; every read is bounds-checked and fails with `StateMalformed`.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < n {
            return Err(CryptoError::StateMalformed);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| CryptoError::StateMalformed)
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(crate) fn str16(&mut self) -> Result<&'a str> {
        let len = usize::from(self.u16()?);
        std::str::from_utf8(self.take(len)?).map_err(|_| CryptoError::StateMalformed)
    }

    pub(crate) fn bytes32(&mut self) -> Result<&'a [u8]> {
        let len = usize::try_from(self.u32()?).map_err(|_| CryptoError::StateMalformed)?;
        self.take(len)
    }

    pub(crate) fn finish(self) -> Result<()> {
        self.buf.is_empty().then_some(()).ok_or(CryptoError::StateMalformed)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    const ULID: &str = "01J9ZK3G5M8Q2W4E6R8T0Y2U4I";

    #[test]
    fn usernames_and_domains() {
        assert!(valid_username("alice"));
        assert!(valid_username("a1.b_c-d"));
        assert!(!valid_username("a"));
        assert!(!valid_username("Alice"));
        assert!(!valid_username("_alice"));
        assert!(!valid_username(&"a".repeat(33)));
        assert!(valid_domain("node.example"));
        assert!(valid_domain("localhost"));
        assert!(!valid_domain("Node.example"));
        assert!(!valid_domain("node.example:443"));
        assert!(!valid_domain("node..example"));
        assert!(!valid_domain("-node.example"));
        assert!(!valid_domain(""));
    }

    #[test]
    fn user_addresses() {
        assert!(valid_user_address("alice@node.example"));
        assert!(!valid_user_address("alice"));
        assert!(!valid_user_address("alice@node.example/x"));
        assert!(!valid_user_address("alice@bob@node.example"));
    }

    #[test]
    fn ulids() {
        assert!(valid_ulid("01J9ZK3G5M8Q2W4E6R8T0Y2V4X"));
        assert!(!valid_ulid(ULID), "I is not Crockford base32");
        assert!(!valid_ulid("81J9ZK3G5M8Q2W4E6R8T0Y2V4X"), "first char > 7 overflows 128 bits");
        assert!(!valid_ulid("01j9zk3g5m8q2w4e6r8t0y2v4x"), "lower case is not canonical");
        assert!(!valid_ulid("01J9ZK3G5M8Q2W4E6R8T0Y2V4"));
    }

    #[test]
    fn conversations_and_device_identities() {
        assert!(valid_conversation("node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V4X"));
        assert!(!valid_conversation("01J9ZK3G5M8Q2W4E6R8T0Y2V4X"));
        assert!(!valid_conversation("node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V4X/x"));
        assert_eq!(
            parse_device_identity("alice@node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V4X"),
            Some(("alice@node.example", "01J9ZK3G5M8Q2W4E6R8T0Y2V4X"))
        );
        assert_eq!(parse_device_identity("alice@node.example"), None);
        assert_eq!(parse_device_identity("alice@node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V4X/x"), None);
    }

    #[test]
    fn base64url_is_strict() {
        assert_eq!(b64url_encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(b64url_decode("-_8").ok(), Some(vec![0xfb, 0xff]));
        assert!(b64url_decode("+/8=").is_err());
        assert!(b64url_decode("a b").is_err());
        assert!(b64url_decode_array::<2>("AAAA", "x").is_err());
    }

    #[test]
    fn aes_roundtrip_and_tamper() {
        let key = [7u8; 32];
        let nonce = [1u8; 12];
        let ct = aes_encrypt(&key, &nonce, b"aad", b"hello").expect("encrypt");
        assert_eq!(aes_decrypt(&key, &nonce, b"aad", &ct).ok(), Some(b"hello".to_vec()));
        assert_eq!(aes_decrypt(&key, &nonce, b"other", &ct), Err(CryptoError::DecryptionFailed));
        assert_eq!(aes_decrypt(&[8u8; 32], &nonce, b"aad", &ct), Err(CryptoError::DecryptionFailed));
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert_eq!(aes_decrypt(&key, &nonce, b"aad", &bad), Err(CryptoError::DecryptionFailed));
        assert_eq!(aes_decrypt(&key, &nonce, b"aad", &[]), Err(CryptoError::DecryptionFailed));
    }

    #[test]
    fn random_arrays_differ() {
        let a = random_array::<32>().expect("rng");
        let b = random_array::<32>().expect("rng");
        assert_ne!(a, b);
    }

    #[test]
    fn reader_is_bounds_checked() {
        let mut out = Vec::new();
        put_str16(&mut out, "hi");
        put_bytes32(&mut out, &[1, 2, 3]).expect("put");
        out.extend_from_slice(&42u64.to_be_bytes());
        let mut r = Reader::new(&out);
        assert_eq!(r.str16().ok(), Some("hi"));
        assert_eq!(r.bytes32().ok(), Some(&[1u8, 2, 3][..]));
        assert_eq!(r.u64().ok(), Some(42));
        assert!(r.finish().is_ok());

        // Length prefix larger than the remaining input.
        let mut r = Reader::new(&[0xff, 0xff, b'a']);
        assert_eq!(r.str16(), Err(CryptoError::StateMalformed));
        let mut r = Reader::new(&[0xff, 0xff, 0xff, 0xff]);
        assert_eq!(r.bytes32(), Err(CryptoError::StateMalformed));
        let r = Reader::new(&[1]);
        assert_eq!(r.finish(), Err(CryptoError::StateMalformed));
        let mut r = Reader::new(&[0, 2, 0xff, 0xfe]);
        assert_eq!(r.str16(), Err(CryptoError::StateMalformed), "invalid UTF-8");
    }
}
