// SPDX-License-Identifier: MPL-2.0
//! Whiteboard scenes of the personal scene library (`protocol/WHITEBOARD.md` §5, ENCRYPTION.md §7a).
//!
//! A scene and its thumbnail are stored on the home node as two blobs, each encrypted under the backup
//! key exactly like a history backup: `version(1) || nonce(12) || AES-256-GCM(plaintext)` with the AAD
//! `"tavrn whiteboard v1\0" || scene id || "\0" || part`, `part` being `scene` or `thumbnail`. The AAD
//! binds a blob to its scene and its role, so the node cannot swap scenes or serve a thumbnail as a scene.
//! The plaintext is opaque to this module (the client stores the scene JSON and a PNG).

use crate::error::{CryptoError, Result};
use crate::keys::BackupKey;
use crate::util::{aes_decrypt, aes_encrypt, random_array};

/// Version byte of a scene blob.
pub const SCENE_VERSION: u8 = 1;
/// AAD prefix of a scene blob (followed by the scene id, a zero byte and the part).
pub const SCENE_AAD: &[u8] = b"tavrn whiteboard v1\0";
/// Smallest valid blob: version, nonce, GCM tag.
pub const SCENE_MIN_BYTES: usize = 1 + 12 + 16;

/// Which blob of a scene.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenePart {
    Scene,
    Thumbnail,
}

impl ScenePart {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "scene" => Ok(Self::Scene),
            "thumbnail" => Ok(Self::Thumbnail),
            _ => Err(CryptoError::InvalidInput("scene part")),
        }
    }

    fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Scene => b"scene",
            Self::Thumbnail => b"thumbnail",
        }
    }
}

/// Scene ids are ULIDs chosen by the client (26 Crockford base32 characters).
fn check_scene_id(id: &str) -> Result<()> {
    let ok = id.len() == 26
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b.is_ascii_uppercase() && !matches!(b, b'I' | b'L' | b'O' | b'U')));
    if ok { Ok(()) } else { Err(CryptoError::InvalidInput("scene id")) }
}

fn aad(scene_id: &str, part: ScenePart) -> Vec<u8> {
    let mut aad = SCENE_AAD.to_vec();
    aad.extend_from_slice(scene_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(part.as_bytes());
    aad
}

/// Encrypts one part of a scene under the backup key.
pub fn encrypt_scene(key: &BackupKey, scene_id: &str, part: ScenePart, plaintext: &[u8]) -> Result<Vec<u8>> {
    encrypt_scene_with_nonce(key, &random_array::<12>()?, scene_id, part, plaintext)
}

/// [`encrypt_scene`] with a caller-chosen nonce (tests only).
pub(crate) fn encrypt_scene_with_nonce(
    key: &BackupKey,
    nonce: &[u8; 12],
    scene_id: &str,
    part: ScenePart,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    check_scene_id(scene_id)?;
    let ciphertext = aes_encrypt(&key.0, nonce, &aad(scene_id, part), plaintext)?;
    let mut out = Vec::with_capacity(13 + ciphertext.len());
    out.push(SCENE_VERSION);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts one part of a scene.
pub fn decrypt_scene(key: &BackupKey, scene_id: &str, part: ScenePart, blob: &[u8]) -> Result<Vec<u8>> {
    check_scene_id(scene_id)?;
    if blob.len() < SCENE_MIN_BYTES {
        return Err(CryptoError::InvalidInput("scene too short"));
    }
    if blob[0] != SCENE_VERSION {
        return Err(CryptoError::UnsupportedVersion);
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[1..13]);
    aes_decrypt(&key.0, &nonce, &aad(scene_id, part), &blob[13..])
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    const ID: &str = "01J9ZK3G5M8Q2W4E6R8T0Y2V4X";
    const OTHER: &str = "01J9ZK3G5M8Q2W4E6R8T0Y2V4Y";

    #[test]
    fn roundtrip_both_parts() {
        let k = BackupKey::from_bytes([7u8; 32]);
        let scene = encrypt_scene(&k, ID, ScenePart::Scene, br#"{"elements":[]}"#).expect("encrypt");
        assert_eq!(scene[0], SCENE_VERSION);
        assert_eq!(scene.len(), SCENE_MIN_BYTES + 15);
        assert_eq!(decrypt_scene(&k, ID, ScenePart::Scene, &scene).expect("decrypt"), br#"{"elements":[]}"#);
        let thumb = encrypt_scene(&k, ID, ScenePart::Thumbnail, b"\x89PNG").expect("encrypt");
        assert_eq!(decrypt_scene(&k, ID, ScenePart::Thumbnail, &thumb).expect("decrypt"), b"\x89PNG");
        let empty = encrypt_scene(&k, ID, ScenePart::Scene, b"").expect("encrypt");
        assert!(decrypt_scene(&k, ID, ScenePart::Scene, &empty).expect("decrypt").is_empty());
    }

    #[test]
    fn blobs_are_bound_to_key_scene_and_part() {
        let k = BackupKey::from_bytes([7u8; 32]);
        let blob = encrypt_scene_with_nonce(&k, &[3u8; 12], ID, ScenePart::Scene, b"scene").expect("encrypt");
        let fail = Some(CryptoError::DecryptionFailed);
        assert_eq!(decrypt_scene(&BackupKey::from_bytes([8u8; 32]), ID, ScenePart::Scene, &blob).err(), fail);
        assert_eq!(decrypt_scene(&k, OTHER, ScenePart::Scene, &blob).err(), fail, "another scene id");
        assert_eq!(decrypt_scene(&k, ID, ScenePart::Thumbnail, &blob).err(), fail, "the thumbnail role");
        let mut tampered = blob.clone();
        tampered[20] ^= 1;
        assert_eq!(decrypt_scene(&k, ID, ScenePart::Scene, &tampered).err(), fail);
        let mut v2 = blob;
        v2[0] = 2;
        assert_eq!(decrypt_scene(&k, ID, ScenePart::Scene, &v2).err(), Some(CryptoError::UnsupportedVersion));
        assert!(decrypt_scene(&k, ID, ScenePart::Scene, &[1, 2, 3]).is_err());
    }

    #[test]
    fn scene_ids_and_parts_are_checked() {
        let k = BackupKey::from_bytes([7u8; 32]);
        for bad in
            ["", "short", "01J9ZK3G5M8Q2W4E6R8T0Y2V4x", "01J9ZK3G5M8Q2W4E6R8T0Y2V4I", "../../../../etc/passwd/xx"]
        {
            assert!(encrypt_scene(&k, bad, ScenePart::Scene, b"x").is_err(), "{bad}");
            assert!(decrypt_scene(&k, bad, ScenePart::Scene, &[1u8; 64]).is_err(), "{bad}");
        }
        assert_eq!(ScenePart::parse("scene").ok(), Some(ScenePart::Scene));
        assert_eq!(ScenePart::parse("thumbnail").ok(), Some(ScenePart::Thumbnail));
        assert!(ScenePart::parse("other").is_err());
    }
}
