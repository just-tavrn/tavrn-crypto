// SPDX-License-Identifier: MPL-2.0
//! Out-of-band identity verification (FEDERATION.md §10.1): safety numbers and the QR payload.
//!
//! Both users compute the same 60-digit number from their addresses and identity public keys; the
//! pairs are sorted by address so the order of the arguments does not matter. The QR payload carries
//! the same four values so that a scanning client can compare them with its own key and its pin.

use sha2::{Digest, Sha256};

use crate::error::{CryptoError, Result};
use crate::util::{b64url_decode_array, b64url_encode, check_user_address, put_str16};

/// Domain separation prefix of the safety number digest.
pub const SAFETY_NUMBER_CONTEXT: &[u8] = b"tavrn safety number v1\0";
/// Prefix of the QR payload.
pub const VERIFY_PAYLOAD_PREFIX: &str = "tavrn:verify?";
/// Number of decimal digits of a safety number.
pub const SAFETY_NUMBER_DIGITS: usize = 60;
/// Longest accepted payload (two maximal addresses, two keys and the labels fit easily).
const MAX_PAYLOAD_LEN: usize = 1024;

/// One verification pair: user address and identity public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyPair {
    /// User address `<username>@<domain>`.
    pub address: String,
    /// Ed25519 identity public key.
    pub identity_key: [u8; 32],
}

/// The content of a `tavrn:verify?...` payload: both pairs, sorted by address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyPayload {
    /// The pair whose address sorts first.
    pub first: VerifyPair,
    /// The pair whose address sorts second.
    pub second: VerifyPair,
}

type Pair<'a> = (&'a str, &'a [u8; 32]);

/// Validates both addresses and sorts the pairs by address (byte-wise UTF-8).
fn sorted<'a>(a: Pair<'a>, b: Pair<'a>) -> Result<[Pair<'a>; 2]> {
    check_user_address(a.0)?;
    check_user_address(b.0)?;
    match a.0.as_bytes().cmp(b.0.as_bytes()) {
        std::cmp::Ordering::Less => Ok([a, b]),
        std::cmp::Ordering::Greater => Ok([b, a]),
        std::cmp::Ordering::Equal => Err(CryptoError::InvalidInput("safety number needs two different addresses")),
    }
}

/// Safety number of two users: 60 decimal digits (FEDERATION.md §10.1). Clients display it as 12
/// groups of 5 digits ([`group_safety_number`]).
pub fn safety_number(address_a: &str, key_a: &[u8; 32], address_b: &str, key_b: &[u8; 32]) -> Result<String> {
    let [(a1, k1), (a2, k2)] = sorted((address_a, key_a), (address_b, key_b))?;
    let mut input = Vec::with_capacity(SAFETY_NUMBER_CONTEXT.len() + 4 + a1.len() + a2.len() + 64);
    input.extend_from_slice(SAFETY_NUMBER_CONTEXT);
    put_str16(&mut input, a1);
    input.extend_from_slice(k1);
    put_str16(&mut input, a2);
    input.extend_from_slice(k2);
    let digest = Sha256::digest(&input);
    Ok(decimal_mod_1e60(&digest))
}

/// `big-endian unsigned integer(bytes) mod 10^60` as 60 decimal digits (left-padded with zeros).
///
/// Horner's scheme over four limbs in base 10^15 (10^60 = (10^15)^4); every intermediate value stays
/// below 2^64 (limb · 256 + carry < 2.6 · 10^17).
fn decimal_mod_1e60(bytes: &[u8]) -> String {
    const BASE: u64 = 1_000_000_000_000_000;
    // Least significant limb first.
    let mut limbs = [0u64; 4];
    for &byte in bytes {
        let mut carry = u64::from(byte);
        for limb in &mut limbs {
            let t = *limb * 256 + carry;
            *limb = t % BASE;
            carry = t / BASE;
        }
        // The carry out of the top limb is a multiple of 10^60: dropped (mod 10^60).
    }
    limbs.iter().rev().map(|l| format!("{l:015}")).collect()
}

/// Splits a 60-digit safety number into 12 groups of 5 digits separated by spaces.
pub fn group_safety_number(number: &str) -> Result<String> {
    if number.len() != SAFETY_NUMBER_DIGITS || !number.bytes().all(|b| b.is_ascii_digit()) {
        return Err(CryptoError::InvalidInput("safety number"));
    }
    let groups: Vec<&str> = (0..12).map(|i| &number[i * 5..i * 5 + 5]).collect();
    Ok(groups.join(" "))
}

/// QR payload `tavrn:verify?v=1&a=<a1>&ka=<k1>&b=<a2>&kb=<k2>` (pairs sorted by address).
pub fn verify_payload(address_a: &str, key_a: &[u8; 32], address_b: &str, key_b: &[u8; 32]) -> Result<String> {
    let [(a1, k1), (a2, k2)] = sorted((address_a, key_a), (address_b, key_b))?;
    Ok(format!("{VERIFY_PAYLOAD_PREFIX}v=1&a={a1}&ka={}&b={a2}&kb={}", b64url_encode(k1), b64url_encode(k2)))
}

/// Parses a QR payload strictly: the exact parameter order of [`verify_payload`], version 1, valid
/// addresses sorted by address, 32-byte keys. Surrounding whitespace (from pasting) is ignored.
pub fn parse_verify_payload(text: &str) -> Result<VerifyPayload> {
    let malformed = CryptoError::InvalidInput("verification payload");
    let text = text.trim();
    if text.len() > MAX_PAYLOAD_LEN {
        return Err(malformed);
    }
    let query = text.strip_prefix(VERIFY_PAYLOAD_PREFIX).ok_or(malformed.clone())?;
    let params: Vec<Option<(&str, &str)>> = query.split('&').map(|p| p.split_once('=')).collect();
    let [Some(("v", "1")), Some(("a", a1)), Some(("ka", k1)), Some(("b", a2)), Some(("kb", k2))] = params.as_slice()
    else {
        return Err(malformed);
    };
    let k1 = b64url_decode_array::<32>(k1, "verification payload key")?;
    let k2 = b64url_decode_array::<32>(k2, "verification payload key")?;
    let [(s1, _), _] = sorted((a1, &k1), (a2, &k2))?;
    if s1 != *a1 {
        return Err(CryptoError::InvalidInput("verification payload is not sorted"));
    }
    Ok(VerifyPayload {
        first: VerifyPair { address: (*a1).to_owned(), identity_key: k1 },
        second: VerifyPair { address: (*a2).to_owned(), identity_key: k2 },
    })
}

/// Scanning rule of FEDERATION.md §10.1: the payload matches only if one pair is the own address
/// with the own current key and the other pair is the contact with the pinned key.
pub fn verify_payload_matches(
    text: &str,
    own_address: &str,
    own_key: &[u8; 32],
    contact_address: &str,
    contact_key: &[u8; 32],
) -> bool {
    let Ok(p) = parse_verify_payload(text) else {
        return false;
    };
    let own = VerifyPair { address: own_address.to_owned(), identity_key: *own_key };
    let contact = VerifyPair { address: contact_address.to_owned(), identity_key: *contact_key };
    own.address != contact.address
        && ((p.first == own && p.second == contact) || (p.first == contact && p.second == own))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    const A: &str = "alice@a.example";
    const B: &str = "bob@b.example";
    const KA: [u8; 32] = [1u8; 32];
    const KB: [u8; 32] = [2u8; 32];

    #[test]
    fn symmetric_and_sixty_digits() {
        let n = safety_number(A, &KA, B, &KB).expect("number");
        assert_eq!(n.len(), 60);
        assert!(n.bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(safety_number(B, &KB, A, &KA).expect("number"), n);
    }

    #[test]
    fn depends_on_every_input() {
        let n = safety_number(A, &KA, B, &KB).expect("number");
        assert_ne!(safety_number(A, &[3u8; 32], B, &KB).expect("n"), n);
        assert_ne!(safety_number(A, &KA, B, &[3u8; 32]).expect("n"), n);
        assert_ne!(safety_number("carol@a.example", &KA, B, &KB).expect("n"), n);
        // Swapping the keys between the addresses changes the number.
        assert_ne!(safety_number(A, &KB, B, &KA).expect("n"), n);
    }

    #[test]
    fn rejects_bad_addresses() {
        assert!(safety_number(A, &KA, A, &KB).is_err());
        assert!(safety_number("alice", &KA, B, &KB).is_err());
        assert!(safety_number(A, &KA, "Bob@b.example", &KB).is_err());
    }

    #[test]
    fn decimal_reduction() {
        assert_eq!(decimal_mod_1e60(&[]), "0".repeat(60));
        assert_eq!(decimal_mod_1e60(&[1, 0]), format!("{:0>60}", 256));
        // 2^256 - 1 = 115792089237316195 423570985008687907853269984665640564039457584007913129639935
        assert_eq!(decimal_mod_1e60(&[0xff; 32]), "423570985008687907853269984665640564039457584007913129639935");
    }

    #[test]
    fn grouping() {
        let n = "012345678901234567890123456789012345678901234567890123456789";
        let g = group_safety_number(n).expect("group");
        assert_eq!(g.split(' ').count(), 12);
        assert!(g.starts_with("01234 56789 01234"));
        assert!(group_safety_number("123").is_err());
        assert!(group_safety_number(&"a".repeat(60)).is_err());
    }

    #[test]
    fn payload_roundtrip_and_matching() {
        let p = verify_payload(B, &KB, A, &KA).expect("payload");
        assert!(p.starts_with("tavrn:verify?v=1&a=alice@a.example&ka="));
        assert_eq!(verify_payload(A, &KA, B, &KB).expect("payload"), p);
        let parsed = parse_verify_payload(&format!("  {p}\n")).expect("parse");
        assert_eq!(parsed.first, VerifyPair { address: A.into(), identity_key: KA });
        assert_eq!(parsed.second, VerifyPair { address: B.into(), identity_key: KB });
        assert!(verify_payload_matches(&p, A, &KA, B, &KB));
        assert!(verify_payload_matches(&p, B, &KB, A, &KA));
        // A different own key, a different pin or a third person: no match.
        assert!(!verify_payload_matches(&p, A, &[9u8; 32], B, &KB));
        assert!(!verify_payload_matches(&p, A, &KA, B, &[9u8; 32]));
        assert!(!verify_payload_matches(&p, A, &KA, "carol@b.example", &KB));
        assert!(!verify_payload_matches(&p, A, &KA, A, &KA));
        assert!(!verify_payload_matches("garbage", A, &KA, B, &KB));
    }

    #[test]
    fn payload_parsing_is_strict() {
        let ka = b64url_encode(&KA);
        let kb = b64url_encode(&KB);
        let bad = [
            format!("tavrn:verify?v=2&a={A}&ka={ka}&b={B}&kb={kb}"),
            format!("tavrn:verify?a={A}&ka={ka}&b={B}&kb={kb}&v=1"),
            format!("tavrn:verify?v=1&a={B}&ka={kb}&b={A}&kb={ka}"),
            format!("tavrn:verify?v=1&a={A}&ka={ka}&b={A}&kb={kb}"),
            format!("tavrn:verify?v=1&a={A}&ka={ka}&b={B}&kb={kb}&x=1"),
            format!("tavrn:verify?v=1&a={A}&ka={ka}&b={B}&kb={kb}&"),
            format!("tavrn:verify?v=1&a={A}&ka=AAAA&b={B}&kb={kb}"),
            format!("tavrn:verify?v=1&a=alice&ka={ka}&b={B}&kb={kb}"),
            format!("https://x/?v=1&a={A}&ka={ka}&b={B}&kb={kb}"),
            format!("tavrn:verify?v=1&a={A}&ka={ka}&b={B}&kb={kb}{}", "A".repeat(2000)),
        ];
        for b in bad {
            assert!(parse_verify_payload(&b).is_err(), "{b}");
        }
    }
}
