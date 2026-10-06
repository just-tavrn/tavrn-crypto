// SPDX-License-Identifier: MPL-2.0
//! Account keys: master secret, key file, identity signing key, backup key and device
//! attestations (ENCRYPTION.md §2 and §3).

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{CryptoError, Result};
use crate::util::{b64url_decode, b64url_encode, check_device_id, check_user_address, put_str16, random_array};

/// HKDF salt for all keys derived from the master secret.
pub const MASTER_SALT: &[u8] = b"tavrn master v1";
/// HKDF info for the identity signing key (Ed25519 seed).
pub const IDENTITY_KEY_INFO: &[u8] = b"tavrn identity key v1";
/// HKDF info for the backup key (AES-256-GCM).
pub const BACKUP_KEY_INFO: &[u8] = b"tavrn backup key v1";
/// Version (kind) byte of the master secret key file payload.
pub const KEY_FILE_VERSION: u8 = 1;
/// First line of every master secret key file.
pub const KEY_FILE_HEADER: &str = "# tavrn security key v1 - keep this file secret and safe";
/// Version (kind) byte of the recovery key payload (same encoding as the key file, other kind).
pub const RECOVERY_KEY_VERSION: u8 = 2;
/// First line of a recovery key file.
pub const RECOVERY_KEY_HEADER: &str = "# tavrn recovery key v1 - keep this key secret and safe";
/// HKDF info of the secret storage wrapping key derived from a recovery key (ENCRYPTION.md §2.4).
pub const RECOVERY_WRAP_INFO: &[u8] = b"tavrn secret storage recovery v1";
/// HKDF info prefix of the local storage key (followed by `0x00 || str16(device id)`).
pub const LOCAL_STORAGE_KEY_INFO: &[u8] = b"tavrn local storage key v1";
/// HKDF info of the key that wraps a rotated identity key for the home node (ENCRYPTION.md §9a).
pub const IDENTITY_WRAP_INFO: &[u8] = b"tavrn identity wrap v1";
/// Domain separation prefix of the identity signature over a device key.
pub const DEVICE_ATTESTATION_CONTEXT: &[u8] = b"tavrn device attestation v1\0";

/// The 32-byte account master secret. Never leaves the client except as a key file.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterSecret([u8; 32]);

impl std::fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterSecret(..)")
    }
}

impl MasterSecret {
    /// Creates a new random master secret (registration or identity reset).
    pub fn generate() -> Result<Self> {
        Ok(Self(random_array()?))
    }

    /// Wraps raw bytes (e.g. from secure storage).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw bytes, for secure local storage only.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0)
    }

    fn derive(&self, info: &[u8]) -> Zeroizing<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(Some(MASTER_SALT), &self.0);
        let mut out = Zeroizing::new([0u8; 32]);
        // 32 bytes is far below the HKDF-SHA256 output limit of 8160 bytes, so expand never fails.
        if hk.expand(info, out.as_mut()).is_err() {
            out.zeroize();
        }
        out
    }

    /// The account identity signing key (Ed25519), derived with [`IDENTITY_KEY_INFO`].
    pub fn identity_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.derive(IDENTITY_KEY_INFO))
    }

    /// The public identity key that the home node publishes.
    pub fn identity_public_key(&self) -> [u8; 32] {
        self.identity_signing_key().verifying_key().to_bytes()
    }

    /// AES-256-GCM key that wraps a rotated identity key (`identity_blob`, ENCRYPTION.md §9a), derived with
    /// [`IDENTITY_WRAP_INFO`]. Every device holding the master secret can unwrap the blob; the node never can.
    pub fn identity_wrap_key(&self) -> Zeroizing<[u8; 32]> {
        self.derive(IDENTITY_WRAP_INFO)
    }

    /// The backup key (AES-256-GCM) for history backups, derived with [`BACKUP_KEY_INFO`].
    pub fn backup_key(&self) -> BackupKey {
        BackupKey(*self.derive(BACKUP_KEY_INFO))
    }

    /// The device-specific key under which a client encrypts its local crypto state (MLS state,
    /// epoch keys, message cache), ENCRYPTION.md §2.1: HKDF from the master secret with
    /// `info = "tavrn local storage key v1" || 0x00 || str16(device_id)`. It never leaves the device.
    pub fn local_storage_key(&self, device_id: &str) -> Result<Zeroizing<[u8; 32]>> {
        check_device_id(device_id)?;
        let mut info = Vec::with_capacity(LOCAL_STORAGE_KEY_INFO.len() + 3 + device_id.len());
        info.extend_from_slice(LOCAL_STORAGE_KEY_INFO);
        info.push(0);
        put_str16(&mut info, device_id);
        Ok(self.derive(&info))
    }

    /// Renders the key file `tavrn-key-<username>.txt`.
    ///
    /// `account` is the user address shown in the file (informational only).
    pub fn to_key_file(&self, account: &str) -> Result<String> {
        render_key_text(
            KEY_FILE_HEADER,
            "Whoever has this file can read your encrypted messages.",
            KEY_FILE_VERSION,
            &self.0,
            account,
        )
    }

    /// Parses a key file, a bare `key:` value or a bare 24-word list.
    ///
    /// Lines starting with `#` and blank lines are ignored. If the file carries both a `key:` and
    /// a `words:` line, both must encode the same secret.
    pub fn from_key_file(text: &str) -> Result<Self> {
        parse_key_text(text, KEY_FILE_VERSION).map(|s| Self(*s))
    }
}

/// Renders a key text (`key:` line with version byte and checksum, `words:` line with the BIP-39
/// words) for a 32-byte secret of the given kind (ENCRYPTION.md §2.2).
fn render_key_text(header: &str, warning: &str, kind: u8, secret: &[u8; 32], account: &str) -> Result<String> {
    check_user_address(account)?;
    let words = key_words(secret)?;
    Ok(format!(
        "{header}\n# Account: {account}\n# {warning}\nkey: {}\nwords: {}\n",
        compact_key(kind, secret).as_str(),
        words.as_str()
    ))
}

/// `base64url(kind || secret || checksum)`, the `key:` value.
fn compact_key(kind: u8, secret: &[u8; 32]) -> Zeroizing<String> {
    let mut payload = Zeroizing::new(Vec::with_capacity(37));
    payload.push(kind);
    payload.extend_from_slice(secret);
    let checksum = key_file_checksum(&payload);
    payload.extend_from_slice(&checksum);
    Zeroizing::new(b64url_encode(&payload))
}

/// The 24 BIP-39 words of a 32-byte secret.
fn key_words(secret: &[u8; 32]) -> Result<Zeroizing<String>> {
    let mnemonic = bip39::Mnemonic::from_entropy(secret).map_err(|_| CryptoError::KeyFileMalformed)?;
    Ok(Zeroizing::new(mnemonic.words().collect::<Vec<_>>().join(" ")))
}

/// Parses a key text of the given kind: a whole file, a bare `key:` value or a bare word list.
fn parse_key_text(text: &str, kind: u8) -> Result<Zeroizing<[u8; 32]>> {
    if text.len() > 4096 {
        return Err(CryptoError::KeyFileMalformed);
    }
    let mut key_line = None;
    let mut words_line = None;
    let mut bare = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        if let Some(v) = line.strip_prefix("key:") {
            key_line = Some(v.trim());
        } else if let Some(v) = line.strip_prefix("words:") {
            words_line = Some(v.trim());
        } else {
            bare.push(line);
        }
    }
    let bare = Zeroizing::new(bare.join(" "));
    if key_line.is_none() && words_line.is_none() {
        if bare.contains(' ') {
            words_line = Some(bare.as_str());
        } else {
            key_line = Some(bare.as_str());
        }
    }
    let from_key = key_line.map(|v| parse_key_value(v, kind)).transpose()?;
    let from_words = words_line.map(parse_words).transpose()?;
    match (from_key, from_words) {
        (Some(a), Some(b)) if *a != *b => Err(CryptoError::KeyFileChecksum),
        (Some(a), _) => Ok(a),
        (None, Some(b)) => Ok(b),
        (None, None) => Err(CryptoError::KeyFileMalformed),
    }
}

fn key_file_checksum(version_and_secret: &[u8]) -> [u8; 4] {
    let digest = Sha256::digest(version_and_secret);
    [digest[0], digest[1], digest[2], digest[3]]
}

fn parse_key_value(value: &str, kind: u8) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(b64url_decode(value).map_err(|_| CryptoError::KeyFileMalformed)?);
    if bytes.len() != 37 {
        return Err(CryptoError::KeyFileMalformed);
    }
    if key_file_checksum(&bytes[..33]) != bytes[33..37] {
        return Err(CryptoError::KeyFileChecksum);
    }
    if bytes[0] != kind {
        return Err(if matches!(bytes[0], KEY_FILE_VERSION | RECOVERY_KEY_VERSION) {
            CryptoError::KeyFileWrongKind
        } else {
            CryptoError::UnsupportedVersion
        });
    }
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&bytes[1..33]);
    Ok(secret)
}

fn parse_words(value: &str) -> Result<Zeroizing<[u8; 32]>> {
    let normalized = Zeroizing::new(value.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase());
    let mnemonic =
        bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &normalized).map_err(|e| match e {
            bip39::Error::InvalidChecksum => CryptoError::KeyFileChecksum,
            _ => CryptoError::KeyFileMalformed,
        })?;
    let (entropy, len) = mnemonic.to_entropy_array();
    let entropy = Zeroizing::new(entropy);
    if len != 32 {
        return Err(CryptoError::KeyFileMalformed);
    }
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&entropy[..32]);
    Ok(secret)
}

/// The recovery key (ENCRYPTION.md §2.4): 32 random bytes, generated by the client, shown to the
/// user once (24 words and a compact string) and never sent to a node. It derives the key that
/// wraps the master secret in the secret storage of the home node.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKey([u8; 32]);

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey(..)")
    }
}

impl RecoveryKey {
    /// A new random recovery key (registration or regeneration).
    pub fn generate() -> Result<Self> {
        Ok(Self(random_array()?))
    }

    /// Wraps raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw bytes (tests and local secure storage only).
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0)
    }

    /// Text of the optional download `tavrn-recovery-<username>.txt` for `account`.
    pub fn to_text(&self, account: &str) -> Result<String> {
        render_key_text(
            RECOVERY_KEY_HEADER,
            "Together with your login it unlocks your encrypted messages on new devices.",
            RECOVERY_KEY_VERSION,
            &self.0,
            account,
        )
    }

    /// The compact form `base64url(0x02 || key || checksum)` (the file's `key:` value).
    pub fn to_compact(&self) -> String {
        compact_key(RECOVERY_KEY_VERSION, &self.0).to_string()
    }

    /// The 24 BIP-39 words (the form shown to the user).
    pub fn to_words(&self) -> Result<String> {
        Ok(key_words(&self.0)?.to_string())
    }

    /// Parses a recovery key file, its compact form or its 24 words (same rules as the key file).
    /// A master secret key file is refused with [`CryptoError::KeyFileWrongKind`].
    pub fn from_text(text: &str) -> Result<Self> {
        parse_key_text(text, RECOVERY_KEY_VERSION).map(|s| Self(*s))
    }

    /// AES-256 key that wraps the master secret for the `recovery` method:
    /// `HKDF-SHA256(salt = none, IKM = recovery key, info = "tavrn secret storage recovery v1")`.
    pub fn wrapping_key(&self) -> Zeroizing<[u8; 32]> {
        hkdf_no_salt(&self.0, RECOVERY_WRAP_INFO)
    }
}

/// `HKDF-SHA256(salt = none, IKM, info)` with 32 bytes of output.
pub(crate) fn hkdf_no_salt(ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    // 32 bytes is far below the HKDF-SHA256 output limit, so expand never fails.
    if hk.expand(info, out.as_mut()).is_err() {
        out.zeroize();
    }
    out
}

/// AES-256-GCM key for history backups.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct BackupKey(pub(crate) [u8; 32]);

impl std::fmt::Debug for BackupKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BackupKey(..)")
    }
}

impl BackupKey {
    /// Wraps raw key bytes (e.g. from local secure storage).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw key bytes, for local secure storage only.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0)
    }
}

/// The identity key's signature over a device key (ENCRYPTION.md §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAttestation {
    /// User address `<username>@<domain>`.
    pub user_address: String,
    /// Device ULID.
    pub device_id: String,
    /// Ed25519 public key of the device (also its MLS signature key).
    pub device_public_key: [u8; 32],
    /// Ed25519 public identity key of the account.
    pub identity_public_key: [u8; 32],
    /// Ed25519 signature by the identity key over [`attestation_message`].
    pub signature: [u8; 64],
}

/// The signed bytes: `"tavrn device attestation v1\0" || device_pubkey(32) || u16 len || device_id
/// || u16 len || user_address`.
pub fn attestation_message(device_public_key: &[u8; 32], device_id: &str, user_address: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(DEVICE_ATTESTATION_CONTEXT.len() + 32 + 4 + device_id.len() + user_address.len());
    msg.extend_from_slice(DEVICE_ATTESTATION_CONTEXT);
    msg.extend_from_slice(device_public_key);
    put_str16(&mut msg, device_id);
    put_str16(&mut msg, user_address);
    msg
}

/// Signs a device key with the account identity key.
pub fn attest_device(
    master: &MasterSecret,
    user_address: &str,
    device_id: &str,
    device_public_key: &[u8; 32],
) -> Result<DeviceAttestation> {
    attest_device_with(&master.identity_signing_key(), user_address, device_id, device_public_key)
}

/// Signs a device key with a given identity signing key (the derived one or a rotated one, ENCRYPTION.md §9a).
pub fn attest_device_with(
    identity: &SigningKey,
    user_address: &str,
    device_id: &str,
    device_public_key: &[u8; 32],
) -> Result<DeviceAttestation> {
    check_user_address(user_address)?;
    check_device_id(device_id)?;
    VerifyingKey::from_bytes(device_public_key).map_err(|_| CryptoError::InvalidInput("device public key"))?;
    let signature = identity.sign(&attestation_message(device_public_key, device_id, user_address));
    Ok(DeviceAttestation {
        user_address: user_address.to_owned(),
        device_id: device_id.to_owned(),
        device_public_key: *device_public_key,
        identity_public_key: identity.verifying_key().to_bytes(),
        signature: signature.to_bytes(),
    })
}

/// Verifies an attestation against the identity key the caller trusts for `user_address`
/// (fetched from the user's home node and pinned). The key inside the attestation is only used
/// if it equals `trusted_identity_key`.
pub fn verify_device_attestation(att: &DeviceAttestation, trusted_identity_key: &[u8; 32]) -> Result<()> {
    check_user_address(&att.user_address)?;
    check_device_id(&att.device_id)?;
    if &att.identity_public_key != trusted_identity_key {
        return Err(CryptoError::BadSignature);
    }
    let key = VerifyingKey::from_bytes(trusted_identity_key).map_err(|_| CryptoError::BadSignature)?;
    let msg = attestation_message(&att.device_public_key, &att.device_id, &att.user_address);
    key.verify_strict(&msg, &Signature::from_bytes(&att.signature)).map_err(|_| CryptoError::BadSignature)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    const ALICE: &str = "alice@node.example";
    const DEV: &str = "01J9ZK3G5M8Q2W4E6R8T0Y2V4X";

    fn fixed() -> MasterSecret {
        MasterSecret::from_bytes([42u8; 32])
    }

    #[test]
    fn derivation_is_deterministic_and_separated() {
        let m = fixed();
        assert_eq!(m.identity_public_key(), fixed().identity_public_key());
        assert_ne!(m.identity_signing_key().to_bytes(), *m.backup_key().to_bytes());
        let other = MasterSecret::from_bytes([43u8; 32]);
        assert_ne!(m.identity_public_key(), other.identity_public_key());
    }

    #[test]
    fn derivation_test_vector() {
        // Pinned so that every implementation derives the same keys (see protocol/testvectors).
        let m = MasterSecret::from_bytes([0u8; 32]);
        let hk = Hkdf::<Sha256>::new(Some(b"tavrn master v1"), &[0u8; 32]);
        let mut seed = [0u8; 32];
        hk.expand(b"tavrn identity key v1", &mut seed).expect("expand");
        assert_eq!(m.identity_signing_key().to_bytes(), seed);
    }

    #[test]
    fn local_storage_key_is_device_specific_and_pinned() {
        let m = fixed();
        let a = m.local_storage_key(DEV).expect("key");
        assert_eq!(*a, *fixed().local_storage_key(DEV).expect("key"), "deterministic");
        assert_ne!(*a, *m.local_storage_key("01J9ZK3G5M8Q2W4E6R8T0Y2V4Y").expect("key"), "per device");
        assert_ne!(*a, *MasterSecret::from_bytes([43u8; 32]).local_storage_key(DEV).expect("key"), "per account");
        assert_ne!(*a, *m.backup_key().to_bytes(), "separated from the backup key");
        // Layout of the info string.
        let hk = Hkdf::<Sha256>::new(Some(b"tavrn master v1"), &[42u8; 32]);
        let mut expected = [0u8; 32];
        let mut info = b"tavrn local storage key v1\0".to_vec();
        info.extend_from_slice(&[0, 26]);
        info.extend_from_slice(DEV.as_bytes());
        hk.expand(&info, &mut expected).expect("expand");
        assert_eq!(*a, expected);
        for bad in ["", "not-a-ulid", "01j9zk3g5m8q2w4e6r8t0y2v4x/"] {
            assert!(m.local_storage_key(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn generate_is_random() {
        let a = MasterSecret::generate().expect("rng");
        let b = MasterSecret::generate().expect("rng");
        assert_ne!(*a.to_bytes(), *b.to_bytes());
    }

    #[test]
    fn key_file_roundtrip() {
        let m = MasterSecret::generate().expect("rng");
        let file = m.to_key_file(ALICE).expect("file");
        assert!(file.starts_with(KEY_FILE_HEADER));
        assert!(file.contains("# Account: alice@node.example"));
        let parsed = MasterSecret::from_key_file(&file).expect("parse");
        assert_eq!(*parsed.to_bytes(), *m.to_bytes());
        // Windows line endings and extra whitespace are fine.
        let crlf = file.replace('\n', "\r\n  ");
        assert_eq!(*MasterSecret::from_key_file(&crlf).expect("crlf").to_bytes(), *m.to_bytes());
    }

    #[test]
    fn key_file_accepts_bare_key_or_words() {
        let m = fixed();
        let file = m.to_key_file(ALICE).expect("file");
        let key = file.lines().find_map(|l| l.strip_prefix("key: ")).expect("key line");
        let words = file.lines().find_map(|l| l.strip_prefix("words: ")).expect("words line");
        assert_eq!(words.split(' ').count(), 24);
        assert_eq!(*MasterSecret::from_key_file(key).expect("key").to_bytes(), [42u8; 32]);
        assert_eq!(*MasterSecret::from_key_file(words).expect("words").to_bytes(), [42u8; 32]);
        let upper = words.to_uppercase().replace(' ', "\n");
        assert_eq!(*MasterSecret::from_key_file(&upper).expect("words").to_bytes(), [42u8; 32]);
    }

    #[test]
    fn key_file_rejects_bad_checksum_and_garbage() {
        let file = fixed().to_key_file(ALICE).expect("file");
        let key = file.lines().find_map(|l| l.strip_prefix("key: ")).expect("key line");
        // Flip one character of the secret part.
        let mut chars: Vec<char> = key.chars().collect();
        chars[10] = if chars[10] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert_eq!(MasterSecret::from_key_file(&tampered).err(), Some(CryptoError::KeyFileChecksum));

        let words = file.lines().find_map(|l| l.strip_prefix("words: ")).expect("words line");
        let mut list: Vec<&str> = words.split(' ').collect();
        list.swap(0, 1);
        let swapped = list.join(" ");
        if swapped != words {
            assert_eq!(MasterSecret::from_key_file(&swapped).err(), Some(CryptoError::KeyFileChecksum));
        }
        assert_eq!(MasterSecret::from_key_file("").err(), Some(CryptoError::KeyFileMalformed));
        assert_eq!(MasterSecret::from_key_file("key: ???").err(), Some(CryptoError::KeyFileMalformed));
        assert_eq!(MasterSecret::from_key_file("not a word list at all").err(), Some(CryptoError::KeyFileMalformed));
        assert_eq!(MasterSecret::from_key_file(&"A".repeat(5000)).err(), Some(CryptoError::KeyFileMalformed));
        // Unknown version byte.
        let mut payload = vec![3u8];
        payload.extend_from_slice(&[0u8; 32]);
        let c = key_file_checksum(&payload);
        payload.extend_from_slice(&c);
        assert_eq!(MasterSecret::from_key_file(&b64url_encode(&payload)).err(), Some(CryptoError::UnsupportedVersion));
    }

    #[test]
    fn key_file_rejects_conflicting_lines() {
        let a = fixed().to_key_file(ALICE).expect("file");
        let b = MasterSecret::from_bytes([1u8; 32]).to_key_file(ALICE).expect("file");
        let key = a.lines().find(|l| l.starts_with("key: ")).expect("key");
        let words = b.lines().find(|l| l.starts_with("words: ")).expect("words");
        let mixed = format!("{key}\n{words}\n");
        assert_eq!(MasterSecret::from_key_file(&mixed).err(), Some(CryptoError::KeyFileChecksum));
    }

    #[test]
    fn key_file_requires_valid_account() {
        assert!(fixed().to_key_file("not an address").is_err());
    }

    #[test]
    fn debug_does_not_leak() {
        assert_eq!(format!("{:?}", fixed()), "MasterSecret(..)");
        assert_eq!(format!("{:?}", fixed().backup_key()), "BackupKey(..)");
        assert_eq!(format!("{:?}", RecoveryKey::from_bytes([1u8; 32])), "RecoveryKey(..)");
    }

    #[test]
    fn recovery_key_roundtrips_in_every_form() {
        let k = RecoveryKey::generate().expect("rng");
        assert_ne!(*k.to_bytes(), *RecoveryKey::generate().expect("rng").to_bytes());
        let text = k.to_text(ALICE).expect("text");
        assert!(text.starts_with(RECOVERY_KEY_HEADER));
        assert!(text.contains("# Account: alice@node.example"));
        assert_eq!(*RecoveryKey::from_text(&text).expect("file").to_bytes(), *k.to_bytes());
        assert_eq!(*RecoveryKey::from_text(&k.to_compact()).expect("compact").to_bytes(), *k.to_bytes());
        let words = k.to_words().expect("words");
        assert_eq!(words.split(' ').count(), 24);
        assert_eq!(*RecoveryKey::from_text(&words.to_uppercase()).expect("words").to_bytes(), *k.to_bytes());
        assert!(text.contains(&format!("key: {}", k.to_compact())));
        assert!(text.contains(&format!("words: {words}")));
    }

    #[test]
    fn recovery_key_and_key_file_are_not_interchangeable() {
        let master_file = fixed().to_key_file(ALICE).expect("file");
        assert_eq!(RecoveryKey::from_text(&master_file).err(), Some(CryptoError::KeyFileWrongKind));
        let recovery = RecoveryKey::from_bytes([42u8; 32]);
        assert_eq!(MasterSecret::from_key_file(&recovery.to_compact()).err(), Some(CryptoError::KeyFileWrongKind));
        // Word lists carry no kind: they decode as either (unwrapping then fails, see secret_storage).
        let words = recovery.to_words().expect("words");
        assert_eq!(*MasterSecret::from_key_file(&words).expect("words").to_bytes(), [42u8; 32]);
    }

    #[test]
    fn recovery_key_rejects_garbage_and_typos() {
        let k = RecoveryKey::from_bytes([5u8; 32]);
        let mut chars: Vec<char> = k.to_compact().chars().collect();
        chars[10] = if chars[10] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert_eq!(RecoveryKey::from_text(&typo).err(), Some(CryptoError::KeyFileChecksum));
        assert_eq!(RecoveryKey::from_text("").err(), Some(CryptoError::KeyFileMalformed));
        assert_eq!(RecoveryKey::from_text("one two three").err(), Some(CryptoError::KeyFileMalformed));
        assert_eq!(RecoveryKey::from_text(&"x".repeat(5000)).err(), Some(CryptoError::KeyFileMalformed));
        assert!(k.to_text("no address").is_err());
    }

    #[test]
    fn recovery_wrapping_key_is_hkdf_of_the_key() {
        let k = RecoveryKey::from_bytes([7u8; 32]);
        let hk = Hkdf::<Sha256>::new(None, &[7u8; 32]);
        let mut expected = [0u8; 32];
        hk.expand(b"tavrn secret storage recovery v1", &mut expected).expect("expand");
        assert_eq!(*k.wrapping_key(), expected);
        assert_ne!(*k.wrapping_key(), *RecoveryKey::from_bytes([8u8; 32]).wrapping_key());
    }

    #[test]
    fn attestation_roundtrip() {
        let m = fixed();
        let device = SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes();
        let att = attest_device(&m, ALICE, DEV, &device).expect("attest");
        assert_eq!(att.identity_public_key, m.identity_public_key());
        verify_device_attestation(&att, &m.identity_public_key()).expect("verify");
    }

    #[test]
    fn forged_attestations_fail() {
        let m = fixed();
        let device = SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes();
        let att = attest_device(&m, ALICE, DEV, &device).expect("attest");
        let trusted = m.identity_public_key();

        // Signed by another identity, claiming to be Alice.
        let mallory = MasterSecret::from_bytes([7u8; 32]);
        let forged = attest_device(&mallory, ALICE, DEV, &device).expect("attest");
        assert_eq!(verify_device_attestation(&forged, &trusted), Err(CryptoError::BadSignature));
        // Same key in the attestation but not trusted.
        let mut swapped = forged.clone();
        swapped.identity_public_key = trusted;
        assert_eq!(verify_device_attestation(&swapped, &trusted), Err(CryptoError::BadSignature));
        // Re-bound to another device, user or key.
        let mut other_device = att.clone();
        other_device.device_id = "01J9ZK3G5M8Q2W4E6R8T0Y2V4Y".into();
        assert_eq!(verify_device_attestation(&other_device, &trusted), Err(CryptoError::BadSignature));
        let mut other_user = att.clone();
        other_user.user_address = "bob@node.example".into();
        assert_eq!(verify_device_attestation(&other_user, &trusted), Err(CryptoError::BadSignature));
        let mut other_key = att.clone();
        other_key.device_public_key = SigningKey::from_bytes(&[10u8; 32]).verifying_key().to_bytes();
        assert_eq!(verify_device_attestation(&other_key, &trusted), Err(CryptoError::BadSignature));
        let mut bad_sig = att;
        bad_sig.signature[0] ^= 1;
        assert_eq!(verify_device_attestation(&bad_sig, &trusted), Err(CryptoError::BadSignature));
    }

    #[test]
    fn attestation_rejects_bad_inputs() {
        let m = fixed();
        let device = SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes();
        assert!(attest_device(&m, "alice", DEV, &device).is_err());
        assert!(attest_device(&m, ALICE, "nope", &device).is_err());
        let mut att = attest_device(&m, ALICE, DEV, &device).expect("attest");
        att.user_address = "alice@node.example/x".into();
        assert_eq!(
            verify_device_attestation(&att, &m.identity_public_key()),
            Err(CryptoError::InvalidInput("user address"))
        );
    }
}
