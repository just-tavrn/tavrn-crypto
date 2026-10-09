// SPDX-License-Identifier: MPL-2.0
//! JavaScript bindings (`wasm-bindgen`), packaged as `@tavrn/crypto` (see `README.md`).
//!
//! Binary values are `Uint8Array`, epochs are `number` (integers below 2^53). Every failure throws
//! a JS `Error` whose `name` is the stable [`CryptoError::code`] (e.g. `"stale_epoch"`) and whose
//! message never contains secret material.

// `getter_with_clone` generates `.clone()` for Copy fields as well.
#![allow(clippy::clone_on_copy)]

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use crate::error::CryptoError;
use crate::{content, file, identity, keys, mls, plaintext, scene, sealed, secret_storage, share, verify};

const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

fn js_err(e: CryptoError) -> JsValue {
    let err = js_sys::Error::new(&e.to_string());
    err.set_name(e.code());
    err.into()
}

type JsResult<T> = Result<T, JsValue>;

fn arr<const N: usize>(bytes: &[u8], what: &'static str) -> JsResult<[u8; N]> {
    bytes.try_into().map_err(|_| js_err(CryptoError::InvalidInput(what)))
}

fn epoch_to_js(epoch: u64) -> JsResult<f64> {
    if epoch > MAX_SAFE_INTEGER {
        return Err(js_err(CryptoError::InvalidInput("epoch too large")));
    }
    // Exact: epoch < 2^53.
    #[allow(clippy::cast_precision_loss)]
    Ok(epoch as f64)
}

fn epoch_from_js(epoch: f64) -> JsResult<u64> {
    #[allow(clippy::cast_precision_loss)]
    let max = MAX_SAFE_INTEGER as f64;
    if !(epoch.is_finite() && epoch >= 0.0 && epoch.fract() == 0.0 && epoch <= max) {
        return Err(js_err(CryptoError::InvalidInput("epoch")));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(epoch as u64)
}

// ---- Keys -----------------------------------------------------------------------------------

/// The account master secret.
#[wasm_bindgen]
pub struct MasterSecret(keys::MasterSecret);

#[wasm_bindgen]
impl MasterSecret {
    /// A new random master secret (registration, identity reset).
    pub fn generate() -> JsResult<MasterSecret> {
        keys::MasterSecret::generate().map(Self).map_err(js_err)
    }

    /// Parses a key file, its `key:` value or its 24-word list.
    #[wasm_bindgen(js_name = fromKeyFile)]
    pub fn from_key_file(text: &str) -> JsResult<MasterSecret> {
        keys::MasterSecret::from_key_file(text).map(Self).map_err(js_err)
    }

    /// Restores from the 32 raw bytes (local secure storage only).
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> JsResult<MasterSecret> {
        Ok(Self(keys::MasterSecret::from_bytes(arr(bytes, "master secret")?)))
    }

    /// The 32 raw bytes (local secure storage only).
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    /// Text of the key file `tavrn-key-<username>.txt` for `account` (`user@domain`).
    #[wasm_bindgen(js_name = toKeyFile)]
    pub fn to_key_file(&self, account: &str) -> JsResult<String> {
        self.0.to_key_file(account).map_err(js_err)
    }

    /// Ed25519 public identity key (32 bytes), published by the home node.
    #[wasm_bindgen(js_name = identityPublicKey)]
    pub fn identity_public_key(&self) -> Vec<u8> {
        self.0.identity_public_key().to_vec()
    }

    /// AES-256 key (32 bytes) for the client's local crypto storage of device `deviceId`.
    #[wasm_bindgen(js_name = localStorageKey)]
    pub fn local_storage_key(&self, device_id: &str) -> JsResult<Vec<u8>> {
        Ok(self.0.local_storage_key(device_id).map_err(js_err)?.to_vec())
    }

    /// AES-256 backup key (32 bytes) for history backups.
    #[wasm_bindgen(js_name = backupKey)]
    pub fn backup_key(&self) -> Vec<u8> {
        self.0.backup_key().to_bytes().to_vec()
    }

    /// Signs a device public key with the identity key; returns the 64-byte signature.
    #[wasm_bindgen(js_name = attestDevice)]
    pub fn attest_device(&self, user_address: &str, device_id: &str, device_public_key: &[u8]) -> JsResult<Vec<u8>> {
        let att = keys::attest_device(&self.0, user_address, device_id, &arr(device_public_key, "device public key")?)
            .map_err(js_err)?;
        Ok(att.signature.to_vec())
    }
}

/// The recovery key that unlocks the secret storage entry `recovery` (ENCRYPTION.md §2.4).
#[wasm_bindgen]
pub struct RecoveryKey(keys::RecoveryKey);

#[wasm_bindgen]
impl RecoveryKey {
    /// A new random recovery key (registration or regeneration).
    pub fn generate() -> JsResult<RecoveryKey> {
        keys::RecoveryKey::generate().map(Self).map_err(js_err)
    }

    /// Parses the 24 words, the compact string or a downloaded recovery key file.
    #[wasm_bindgen(js_name = fromText)]
    pub fn from_text(text: &str) -> JsResult<RecoveryKey> {
        keys::RecoveryKey::from_text(text).map(Self).map_err(js_err)
    }

    /// The 24 words shown to the user.
    #[wasm_bindgen(js_name = toWords)]
    pub fn to_words(&self) -> JsResult<String> {
        self.0.to_words().map_err(js_err)
    }

    /// The compact string (base64url with version byte and checksum).
    #[wasm_bindgen(js_name = toCompact)]
    pub fn to_compact(&self) -> String {
        self.0.to_compact()
    }

    /// Text of the optional download `tavrn-recovery-<username>.txt` for `account` (`user@domain`).
    #[wasm_bindgen(js_name = toText)]
    pub fn to_text(&self, account: &str) -> JsResult<String> {
        self.0.to_text(account).map_err(js_err)
    }

    /// AES-256 wrapping key (32 bytes) of the `recovery` method.
    #[wasm_bindgen(js_name = wrappingKey)]
    pub fn wrapping_key(&self) -> Vec<u8> {
        self.0.wrapping_key().to_vec()
    }
}

/// Wraps the master secret for the secret storage method `method` (`recovery` or
/// `passkey:<credential id>`) of `userAddress`; returns the bytes to upload (base64url).
#[wasm_bindgen(js_name = wrapMasterSecret)]
pub fn wrap_master_secret(
    master: &MasterSecret,
    wrapping_key: &[u8],
    user_address: &str,
    method: &str,
) -> JsResult<Vec<u8>> {
    secret_storage::wrap_master_secret(&master.0, &arr(wrapping_key, "wrapping key")?, user_address, method)
        .map_err(js_err)
}

/// Unwraps a secret storage entry fetched from the home node.
#[wasm_bindgen(js_name = unwrapMasterSecret)]
pub fn unwrap_master_secret(
    wrapped: &[u8],
    wrapping_key: &[u8],
    user_address: &str,
    method: &str,
) -> JsResult<MasterSecret> {
    secret_storage::unwrap_master_secret(wrapped, &arr(wrapping_key, "wrapping key")?, user_address, method)
        .map(MasterSecret)
        .map_err(js_err)
}

/// Wrapping key (32 bytes) of a `passkey:<credential id>` entry from the 32-byte WebAuthn PRF output.
#[wasm_bindgen(js_name = passkeyWrappingKey)]
pub fn passkey_wrapping_key(prf_output: &[u8]) -> JsResult<Vec<u8>> {
    Ok(secret_storage::passkey_wrapping_key(prf_output).map_err(js_err)?.to_vec())
}

/// The input to pass as `extensions.prf.eval.first` in every WebAuthn ceremony.
#[wasm_bindgen(js_name = secretStoragePrfInput)]
pub fn secret_storage_prf_input() -> Vec<u8> {
    secret_storage::PRF_INPUT.to_vec()
}

/// Method label `passkey:<credential id>` for a base64url credential id.
#[wasm_bindgen(js_name = passkeyMethod)]
pub fn passkey_method(credential_id: &str) -> JsResult<String> {
    secret_storage::passkey_method(credential_id).map_err(js_err)
}

/// Checks an identity signature over a device key against the trusted (pinned) identity key.
#[wasm_bindgen(js_name = verifyDeviceAttestation)]
pub fn verify_device_attestation(
    user_address: &str,
    device_id: &str,
    device_public_key: &[u8],
    signature: &[u8],
    trusted_identity_key: &[u8],
) -> bool {
    let (Ok(device_public_key), Ok(signature), Ok(identity)) =
        (arr::<32>(device_public_key, "key"), arr::<64>(signature, "sig"), arr::<32>(trusted_identity_key, "key"))
    else {
        return false;
    };
    let att = keys::DeviceAttestation {
        user_address: user_address.to_owned(),
        device_id: device_id.to_owned(),
        device_public_key,
        identity_public_key: identity,
        signature,
    };
    keys::verify_device_attestation(&att, &identity).is_ok()
}

// ---- Identity rotation (ENCRYPTION.md §9a) ------------------------------------------------------

/// An identity signing key of any generation (derived from the master secret, or rotated).
#[wasm_bindgen]
pub struct IdentityKey(identity::IdentityKey);

#[wasm_bindgen]
impl IdentityKey {
    /// A fresh random identity key (rotation).
    pub fn generate() -> JsResult<IdentityKey> {
        identity::IdentityKey::generate().map(Self).map_err(js_err)
    }

    /// Generation 0: the key derived from the master secret.
    #[wasm_bindgen(js_name = fromMaster)]
    pub fn from_master(master: &MasterSecret) -> IdentityKey {
        Self(identity::IdentityKey::from_master(&master.0))
    }

    /// From the 32-byte seed (local secure storage only).
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> JsResult<IdentityKey> {
        Ok(Self(identity::IdentityKey::from_seed(&arr(bytes, "identity seed")?)))
    }

    /// The 32-byte seed (local secure storage only).
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_seed().to_vec()
    }

    /// Ed25519 public identity key (32 bytes).
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.0.public_key().to_vec()
    }

    /// Signs a device public key with this identity key; returns the 64-byte signature.
    #[wasm_bindgen(js_name = attestDevice)]
    pub fn attest_device(&self, user_address: &str, device_id: &str, device_public_key: &[u8]) -> JsResult<Vec<u8>> {
        let att = self
            .0
            .attest_device(user_address, device_id, &arr(device_public_key, "device public key")?)
            .map_err(js_err)?;
        Ok(att.signature.to_vec())
    }
}

/// Wraps a rotated identity key for the home node (`identity_blob`, 61 bytes).
#[wasm_bindgen(js_name = wrapIdentityKey)]
pub fn wrap_identity_key(master: &MasterSecret, key: &IdentityKey, user_address: &str) -> JsResult<Vec<u8>> {
    identity::wrap_identity_key(&master.0, &key.0, user_address).map_err(js_err)
}

/// Unwraps an `identity_blob`; the caller checks the public key against the published one.
#[wasm_bindgen(js_name = unwrapIdentityKey)]
pub fn unwrap_identity_key(master: &MasterSecret, blob: &[u8], user_address: &str) -> JsResult<IdentityKey> {
    identity::unwrap_identity_key(&master.0, blob, user_address).map(IdentityKey).map_err(js_err)
}

/// Signs the continuity statement `old → new` at `at` (RFC 3339) with both keys; returns its JSON
/// `{ old_key, new_key, at, sig_old, sig_new }`.
#[wasm_bindgen(js_name = signContinuity)]
pub fn sign_continuity(old: &IdentityKey, new: &IdentityKey, at: &str) -> JsResult<String> {
    let s = identity::sign_continuity(&old.0, &new.0, at).map_err(js_err)?;
    serde_json::to_string(&s).map_err(|_| js_err(CryptoError::InvalidInput("continuity statement")))
}

/// Checks both signatures of one statement (JSON); false for anything malformed.
#[wasm_bindgen(js_name = verifyContinuity)]
pub fn verify_continuity(statement_json: &str) -> bool {
    serde_json::from_str::<identity::ContinuityStatement>(statement_json)
        .is_ok_and(|s| identity::verify_continuity(&s).is_ok())
}

/// Is `to` reachable from `from` through valid consecutive statements of `chain` (JSON array, oldest first)?
#[wasm_bindgen(js_name = continuityReaches)]
pub fn continuity_reaches(chain_json: &str, from: &str, to: &str) -> bool {
    serde_json::from_str::<Vec<identity::ContinuityStatement>>(chain_json)
        .is_ok_and(|chain| identity::continuity_reaches(&chain, from, to))
}

// ---- Files and content headers --------------------------------------------------------------

/// An encrypted attachment: upload `ciphertext`, put `key`, `nonce`, `sha256` into the content.
#[wasm_bindgen(getter_with_clone)]
pub struct EncryptedFile {
    pub ciphertext: Vec<u8>,
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub sha256: Vec<u8>,
}

/// Encrypts a file with a fresh random key (AES-256-GCM, one shot).
#[wasm_bindgen(js_name = encryptFile)]
pub fn encrypt_file(plaintext: &[u8]) -> JsResult<EncryptedFile> {
    let f = file::encrypt_file(plaintext).map_err(js_err)?;
    Ok(EncryptedFile {
        ciphertext: f.ciphertext.clone(),
        key: f.key.to_vec(),
        nonce: f.nonce.to_vec(),
        sha256: f.sha256.to_vec(),
    })
}

/// Checks the ciphertext hash and decrypts an attachment.
#[wasm_bindgen(js_name = decryptFile)]
pub fn decrypt_file(ciphertext: &[u8], key: &[u8], nonce: &[u8], sha256: &[u8]) -> JsResult<Vec<u8>> {
    file::decrypt_file(ciphertext, &arr(key, "file key")?, &arr(nonce, "nonce")?, &arr(sha256, "sha256")?)
        .map_err(js_err)
}

/// Encrypts one part (`"scene"` or `"thumbnail"`) of a whiteboard scene under the backup key
/// (`protocol/WHITEBOARD.md` §5).
#[wasm_bindgen(js_name = encryptScene)]
pub fn encrypt_scene(backup_key: &[u8], scene_id: &str, part: &str, plaintext: &[u8]) -> JsResult<Vec<u8>> {
    let key = keys::BackupKey::from_bytes(arr(backup_key, "backup key")?);
    scene::encrypt_scene(&key, scene_id, scene::ScenePart::parse(part).map_err(js_err)?, plaintext).map_err(js_err)
}

/// Decrypts one part of a whiteboard scene.
#[wasm_bindgen(js_name = decryptScene)]
pub fn decrypt_scene(backup_key: &[u8], scene_id: &str, part: &str, blob: &[u8]) -> JsResult<Vec<u8>> {
    let key = keys::BackupKey::from_bytes(arr(backup_key, "backup key")?);
    scene::decrypt_scene(&key, scene_id, scene::ScenePart::parse(part).map_err(js_err)?, blob).map_err(js_err)
}

/// Inbox public key of write-only webhooks for the epoch whose content key is `content_key` (ENCRYPTION.md §5b;
/// test vectors and tools, clients use `Client.inboxKey`).
#[wasm_bindgen(js_name = inboxPublicKey)]
pub fn inbox_public_key(content_key: &[u8]) -> JsResult<Vec<u8>> {
    Ok(sealed::inbox_public_key(&arr(content_key, "content key")?).to_vec())
}

/// libsodium `crypto_box_seal` to an inbox public key: what a webhook sender does (ENCRYPTION.md §5b).
#[wasm_bindgen(js_name = sealToInbox)]
pub fn seal_to_inbox(public_key: &[u8], plaintext: &[u8]) -> JsResult<Vec<u8>> {
    sealed::seal(&arr(public_key, "public key")?, plaintext).map_err(js_err)
}

/// Checks a device's published share key against its (verified) device key (ENCRYPTION.md §3.1): clients seal
/// nothing to a share key whose signature does not verify.
#[wasm_bindgen(js_name = verifyDeviceShareKey)]
pub fn verify_device_share_key(
    device_id: &str,
    device_public_key: &[u8],
    share_public_key: &[u8],
    signature: &[u8],
) -> JsResult<bool> {
    let device_key = arr::<32>(device_public_key, "device public key")?;
    let share_key = arr::<32>(share_public_key, "share public key")?;
    Ok(share::verify_share_key(&device_key, device_id, &share_key, signature).is_ok())
}

/// Seals the fresh key of a history share v2 to one recipient device's share public key (ENCRYPTION.md §7b).
#[wasm_bindgen(js_name = sealShareKey)]
pub fn seal_share_key(share_public_key: &[u8], key: &[u8]) -> JsResult<Vec<u8>> {
    share::seal_share_key(&arr(share_public_key, "share public key")?, &arr(key, "share key")?).map_err(js_err)
}

/// Decrypts content format 1 under an explicit key (a history share v2 under the key from its box) and verifies the
/// device signature; nothing is stored.
#[wasm_bindgen(js_name = decryptContentWithKey)]
pub fn decrypt_content_with_key(
    key: &[u8],
    conversation: &str,
    author: &str,
    device_id: &str,
    content: &str,
    device_public_key: &[u8],
) -> JsResult<String> {
    let key = zeroize::Zeroizing::new(arr::<32>(key, "share key")?);
    let device_key = arr::<32>(device_public_key, "device public key")?;
    share::decrypt_content_with_key(&key, conversation, author, device_id, content, &device_key).map_err(js_err)
}

/// The share secret key a device derives from its device secret (ENCRYPTION.md §3.1; test vectors and tools, clients
/// use `Client.shareKey` and `Client.openShareBox`).
#[wasm_bindgen(js_name = deviceShareSecretKey)]
pub fn device_share_secret_key(device_secret_key: &[u8]) -> JsResult<Vec<u8>> {
    let secret = zeroize::Zeroizing::new(arr::<32>(device_secret_key, "device secret key")?);
    Ok(share::share_secret(&secret).to_vec())
}

/// The X25519 public key of a share secret key.
#[wasm_bindgen(js_name = sharePublicKey)]
pub fn share_public_key(share_secret_key: &[u8]) -> JsResult<Vec<u8>> {
    let secret = zeroize::Zeroizing::new(arr::<32>(share_secret_key, "share secret key")?);
    Ok(share::share_public_key(&secret).to_vec())
}

/// Opens a sealed share key with a raw share secret key (test vectors and tools; clients use `Client.openShareBox`).
#[wasm_bindgen(js_name = openShareBox)]
pub fn open_share_box(share_secret_key: &[u8], sealed: &[u8]) -> JsResult<Vec<u8>> {
    let secret = zeroize::Zeroizing::new(arr::<32>(share_secret_key, "share secret key")?);
    Ok(share::open_share_box(&secret, sealed).map_err(js_err)?.to_vec())
}

/// A device's share key with the device signature over it (`PUT /users/me/devices/{id}/share-key`).
#[wasm_bindgen(getter_with_clone)]
pub struct ShareKey {
    #[wasm_bindgen(js_name = publicKey)]
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

/// A history share v2: the content and the share key sealed to each recipient device, in the order of the share keys
/// passed to `Client.encryptShare` (the key itself never leaves the WebAssembly module).
#[wasm_bindgen(getter_with_clone)]
pub struct EncryptedShare {
    pub content: String,
    pub epoch: f64,
    pub boxes: Vec<Uint8Array>,
}

/// A published inbox key: `PUT /conversations/{id}/inbox-key` (ENCRYPTION.md §5b).
#[wasm_bindgen(getter_with_clone)]
pub struct InboxKey {
    #[wasm_bindgen(js_name = publicKey)]
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Epoch from the plaintext header of an encrypted `content` value.
#[wasm_bindgen(js_name = contentEpoch)]
pub fn content_epoch(content_b64: &str) -> JsResult<f64> {
    epoch_to_js(content::content_header(content_b64).map_err(js_err)?.epoch)
}

/// Capability string of this scheme (`e2ee.mls1`).
#[wasm_bindgen(js_name = capability)]
pub fn capability() -> String {
    crate::CAPABILITY.to_owned()
}

// ---- Identity verification and plaintext signatures (FEDERATION.md §10) ---------------------

/// Safety number of two users (60 digits; display as 12 groups of 5). Argument order is irrelevant.
#[wasm_bindgen(js_name = safetyNumber)]
pub fn safety_number(address_a: &str, key_a: &[u8], address_b: &str, key_b: &[u8]) -> JsResult<String> {
    verify::safety_number(address_a, &arr(key_a, "identity key")?, address_b, &arr(key_b, "identity key")?)
        .map_err(js_err)
}

/// QR payload `tavrn:verify?v=1&a=…&ka=…&b=…&kb=…` of two users.
#[wasm_bindgen(js_name = verifyPayload)]
pub fn verify_payload(address_a: &str, key_a: &[u8], address_b: &str, key_b: &[u8]) -> JsResult<String> {
    verify::verify_payload(address_a, &arr(key_a, "identity key")?, address_b, &arr(key_b, "identity key")?)
        .map_err(js_err)
}

/// A parsed QR payload; keys are base64url.
#[wasm_bindgen(getter_with_clone)]
pub struct VerifyPayload {
    pub a: String,
    pub ka: String,
    pub b: String,
    pub kb: String,
}

/// Parses a QR payload strictly (throws `invalid_input` for anything malformed).
#[wasm_bindgen(js_name = parseVerifyPayload)]
pub fn parse_verify_payload(text: &str) -> JsResult<VerifyPayload> {
    let p = verify::parse_verify_payload(text).map_err(js_err)?;
    Ok(VerifyPayload {
        a: p.first.address,
        ka: crate::util::b64url_encode(&p.first.identity_key),
        b: p.second.address,
        kb: crate::util::b64url_encode(&p.second.identity_key),
    })
}

/// True if the payload names exactly the own address with the own key and the contact with the
/// pinned key (FEDERATION.md §10.1).
#[wasm_bindgen(js_name = verifyPayloadMatches)]
pub fn verify_payload_matches(
    text: &str,
    own_address: &str,
    own_key: &[u8],
    contact_address: &str,
    contact_key: &[u8],
) -> bool {
    let (Ok(own_key), Ok(contact_key)) = (arr::<32>(own_key, "key"), arr::<32>(contact_key, "key")) else {
        return false;
    };
    verify::verify_payload_matches(text, own_address, &own_key, contact_address, &contact_key)
}

/// RFC 8785 (JCS) form of a JSON text.
#[wasm_bindgen(js_name = canonicalJson)]
pub fn canonical_json(json: &str) -> JsResult<String> {
    plaintext::canonical_json(json).map_err(js_err)
}

fn plaintext_fields(fields_json: &str) -> JsResult<plaintext::PlaintextFields> {
    serde_json::from_str(fields_json).map_err(|_| js_err(CryptoError::InvalidInput("plaintext fields")))
}

/// Verifies the `signature` of a plaintext message. `fieldsJson` holds the envelope fields
/// (`conversation`, `author`, `device_id`, `reply_to`, `thread_id`, `mentions_everyone`, `mentions`,
/// `attachments`), `contentJcs` the content object in RFC 8785 form (checked against this
/// implementation). Returns false for a wrong signature; throws for malformed input.
#[wasm_bindgen(js_name = verifyPlaintext)]
pub fn verify_plaintext(
    fields_json: &str,
    content_jcs: &str,
    signature: &str,
    device_public_key: &[u8],
) -> JsResult<bool> {
    let fields = plaintext_fields(fields_json)?;
    let content = plaintext::parse_canonical_content(content_jcs).map_err(js_err)?;
    let key = arr::<32>(device_public_key, "device public key")?;
    match plaintext::verify_plaintext(&fields, &content, signature, &key) {
        Ok(_) => Ok(true),
        Err(CryptoError::BadSignature) => Ok(false),
        Err(e) => Err(js_err(e)),
    }
}

// ---- MLS client -----------------------------------------------------------------------------

/// Messages produced by a commit; see [`mls::CommitOutput`].
#[wasm_bindgen(getter_with_clone)]
pub struct CommitOutput {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    #[wasm_bindgen(js_name = groupInfo)]
    pub group_info: Vec<u8>,
    pub epoch: f64,
}

impl CommitOutput {
    fn from_native(o: mls::CommitOutput) -> JsResult<Self> {
        Ok(Self { epoch: epoch_to_js(o.epoch)?, commit: o.commit, welcome: o.welcome, group_info: o.group_info })
    }
}

/// Result of processing a commit; see [`mls::HandshakeOutcome`].
#[wasm_bindgen(getter_with_clone)]
pub struct HandshakeOutcome {
    pub epoch: f64,
    pub committer: String,
    #[wasm_bindgen(js_name = externalJoin)]
    pub external_join: bool,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    #[wasm_bindgen(js_name = selfRemoved)]
    pub self_removed: bool,
    #[wasm_bindgen(js_name = discardedPendingCommit)]
    pub discarded_pending_commit: bool,
}

/// Result of joining by Welcome.
#[wasm_bindgen(getter_with_clone)]
pub struct WelcomeJoin {
    pub conversation: String,
    pub epoch: f64,
}

/// A member leaf of a group.
#[wasm_bindgen(getter_with_clone)]
#[derive(Clone)]
pub struct RosterEntry {
    pub identity: String,
    #[wasm_bindgen(js_name = signatureKey)]
    pub signature_key: Vec<u8>,
}

/// The MLS client of this device. Persist `exportState()` after every mutating call.
#[wasm_bindgen]
pub struct Client(mls::Client);

#[wasm_bindgen]
impl Client {
    /// A new device: generates its Ed25519 key.
    pub fn create(user_address: &str, device_id: &str) -> JsResult<Client> {
        Ok(Self(mls::Client::new(crate::Device::generate(user_address, device_id).map_err(js_err)?)))
    }

    /// Restores a client from `exportState()` bytes.
    #[wasm_bindgen(js_name = importState)]
    pub fn import_state(state: &[u8]) -> JsResult<Client> {
        mls::Client::import_state(state).map(Self).map_err(js_err)
    }

    /// Serializes the whole client state (secret!).
    #[wasm_bindgen(js_name = exportState)]
    pub fn export_state(&self) -> JsResult<Vec<u8>> {
        Ok(self.0.export_state().map_err(js_err)?.to_vec())
    }

    /// `<user>@<domain>/<device_id>`.
    #[wasm_bindgen(getter)]
    pub fn identity(&self) -> String {
        self.0.device().identity()
    }

    #[wasm_bindgen(getter, js_name = userAddress)]
    pub fn user_address(&self) -> String {
        self.0.device().user_address().to_owned()
    }

    #[wasm_bindgen(getter, js_name = deviceId)]
    pub fn device_id(&self) -> String {
        self.0.device().device_id().to_owned()
    }

    /// Ed25519 device public key (32 bytes) = MLS leaf signature key.
    #[wasm_bindgen(getter, js_name = devicePublicKey)]
    pub fn device_public_key(&self) -> Vec<u8> {
        self.0.device().public_key().to_vec()
    }

    /// Device login proof over the node's login nonce (ENCRYPTION.md §3.4), 64 bytes.
    #[wasm_bindgen(js_name = signDeviceLogin)]
    pub fn sign_device_login(&self, nonce: &str) -> JsResult<Vec<u8>> {
        Ok(self.0.device().sign_login(nonce).map_err(js_err)?.to_vec())
    }

    #[wasm_bindgen(js_name = createKeyPackage)]
    pub fn create_key_package(&self) -> JsResult<Vec<u8>> {
        self.0.create_key_package().map_err(js_err)
    }

    #[wasm_bindgen(js_name = hasGroup)]
    pub fn has_group(&self, conversation: &str) -> bool {
        self.0.has_group(conversation)
    }

    /// Creates the group at epoch 0; returns its GroupInfo.
    #[wasm_bindgen(js_name = createGroup)]
    pub fn create_group(&mut self, conversation: &str) -> JsResult<Vec<u8>> {
        self.0.create_group(conversation).map_err(js_err)
    }

    #[wasm_bindgen(js_name = joinByExternalCommit)]
    pub fn join_by_external_commit(&mut self, conversation: &str, group_info: &[u8]) -> JsResult<CommitOutput> {
        CommitOutput::from_native(self.0.join_by_external_commit(conversation, group_info).map_err(js_err)?)
    }

    #[wasm_bindgen(js_name = joinByWelcome)]
    pub fn join_by_welcome(&mut self, welcome: &[u8]) -> JsResult<WelcomeJoin> {
        let (conversation, epoch) = self.0.join_by_welcome(welcome).map_err(js_err)?;
        Ok(WelcomeJoin { conversation, epoch: epoch_to_js(epoch)? })
    }

    #[wasm_bindgen(js_name = addMembers)]
    pub fn add_members(&mut self, conversation: &str, key_packages: Vec<Uint8Array>) -> JsResult<CommitOutput> {
        let kps: Vec<Vec<u8>> = key_packages.iter().map(Uint8Array::to_vec).collect();
        CommitOutput::from_native(self.0.add_members(conversation, &kps).map_err(js_err)?)
    }

    #[wasm_bindgen(js_name = removeMembers)]
    pub fn remove_members(&mut self, conversation: &str, identities: Vec<String>) -> JsResult<CommitOutput> {
        CommitOutput::from_native(self.0.remove_members(conversation, &identities).map_err(js_err)?)
    }

    #[wasm_bindgen(js_name = selfUpdate)]
    pub fn self_update(&mut self, conversation: &str) -> JsResult<CommitOutput> {
        CommitOutput::from_native(self.0.self_update(conversation).map_err(js_err)?)
    }

    #[wasm_bindgen(js_name = mergePendingCommit)]
    pub fn merge_pending_commit(&mut self, conversation: &str) -> JsResult<f64> {
        epoch_to_js(self.0.merge_pending_commit(conversation).map_err(js_err)?)
    }

    #[wasm_bindgen(js_name = discardPendingCommit)]
    pub fn discard_pending_commit(&mut self, conversation: &str) -> JsResult<()> {
        self.0.discard_pending_commit(conversation).map_err(js_err)
    }

    #[wasm_bindgen(js_name = processHandshake)]
    pub fn process_handshake(&mut self, conversation: &str, message: &[u8]) -> JsResult<HandshakeOutcome> {
        let o = self.0.process_handshake(conversation, message).map_err(js_err)?;
        Ok(HandshakeOutcome {
            epoch: epoch_to_js(o.epoch)?,
            committer: o.committer,
            external_join: o.external_join,
            added: o.added,
            removed: o.removed,
            self_removed: o.self_removed,
            discarded_pending_commit: o.discarded_pending_commit,
        })
    }

    #[wasm_bindgen(js_name = currentEpoch)]
    pub fn current_epoch(&self, conversation: &str) -> JsResult<f64> {
        epoch_to_js(self.0.current_epoch(conversation).map_err(js_err)?)
    }

    pub fn roster(&self, conversation: &str) -> JsResult<Vec<RosterEntry>> {
        Ok(self
            .0
            .roster(conversation)
            .map_err(js_err)?
            .into_iter()
            .map(|e| RosterEntry { identity: e.identity, signature_key: e.signature_key.to_vec() })
            .collect())
    }

    #[wasm_bindgen(js_name = deleteGroup)]
    pub fn delete_group(&mut self, conversation: &str) -> JsResult<()> {
        self.0.delete_group(conversation).map_err(js_err)
    }

    /// Signs a plaintext message with this device (FEDERATION.md §10.3); returns the envelope value
    /// `signature`. `fieldsJson` as for `verifyPlaintext` (author and device must be this device's).
    #[wasm_bindgen(js_name = signPlaintext)]
    pub fn sign_plaintext(&self, fields_json: &str, content_jcs: &str) -> JsResult<String> {
        let fields = plaintext_fields(fields_json)?;
        let content = plaintext::parse_canonical_content(content_jcs).map_err(js_err)?;
        Ok(plaintext::sign_plaintext(self.0.device(), &fields, &content).map_err(js_err)?.to_base64url())
    }

    /// Encrypts a JSON content object; returns the base64url `content` value.
    #[wasm_bindgen(js_name = encryptContent)]
    pub fn encrypt_content(&self, conversation: &str, json: &str) -> JsResult<String> {
        self.0.encrypt_content(conversation, json).map_err(js_err)
    }

    /// Decrypts and verifies `content`. Pass `devicePublicKey` (from the verified attestation)
    /// when the author device is no longer in the roster.
    #[wasm_bindgen(js_name = decryptContent)]
    pub fn decrypt_content(
        &self,
        conversation: &str,
        author: &str,
        device_id: &str,
        content: &str,
        device_public_key: Option<Vec<u8>>,
    ) -> JsResult<String> {
        let key = device_public_key.map(|k| arr::<32>(&k, "device public key")).transpose()?;
        self.0.decrypt_content(conversation, author, device_id, content, key.as_ref()).map_err(js_err)
    }

    #[wasm_bindgen(js_name = exportEpochKey)]
    pub fn export_epoch_key(&self, conversation: &str, epoch: f64) -> JsResult<Vec<u8>> {
        Ok(self.0.export_epoch_key(conversation, epoch_from_js(epoch)?).map_err(js_err)?.to_vec())
    }

    /// Voice frame key of the current epoch (32 bytes, ENCRYPTION.md §5a) for LiveKit's key provider at
    /// key index `epoch % 256`. Fails unless `epoch` is the group's current epoch.
    #[wasm_bindgen(js_name = exportVoiceKey)]
    pub fn export_voice_key(&self, conversation: &str, epoch: f64) -> JsResult<Vec<u8>> {
        Ok(self.0.export_voice_key(conversation, epoch_from_js(epoch)?).map_err(js_err)?.to_vec())
    }

    /// This device's share key and the device signature over it (ENCRYPTION.md §3.1).
    #[wasm_bindgen(js_name = shareKey)]
    pub fn share_key(&self) -> ShareKey {
        let device = self.0.device();
        ShareKey { public_key: device.share_public_key().to_vec(), signature: device.share_key_signature().to_vec() }
    }

    /// A history share v2 (ENCRYPTION.md §7b): `json` encrypted and signed like content of the current epoch under a
    /// fresh key, which is sealed to each of `share_public_keys` (verified share keys of the recipient's devices) and
    /// then zeroed.
    #[wasm_bindgen(js_name = encryptShare)]
    pub fn encrypt_share(
        &self,
        conversation: &str,
        json: &str,
        share_public_keys: Vec<Uint8Array>,
    ) -> JsResult<EncryptedShare> {
        let recipients = share_public_keys
            .iter()
            .map(|k| arr::<32>(&k.to_vec(), "share public key"))
            .collect::<JsResult<Vec<[u8; 32]>>>()?;
        if recipients.is_empty() {
            return Err(js_err(CryptoError::InvalidInput("no recipient devices")));
        }
        let (content, key) = self.0.encrypt_share(conversation, json).map_err(js_err)?;
        let epoch = content::content_header(&content).map_err(js_err)?.epoch;
        let boxes = recipients
            .iter()
            .map(|pk| share::seal_share_key(pk, &key).map(|b| Uint8Array::from(b.as_slice())))
            .collect::<Result<Vec<_>, _>>()
            .map_err(js_err)?;
        Ok(EncryptedShare { content, epoch: epoch_to_js(epoch)?, boxes })
    }

    /// Opens a sealed share key addressed to this device; returns the 32-byte key (`decryption_failed` otherwise).
    #[wasm_bindgen(js_name = openShareBox)]
    pub fn open_share_box(&self, sealed: &[u8]) -> JsResult<Vec<u8>> {
        Ok(self.0.open_share_box(sealed).map_err(js_err)?.to_vec())
    }

    /// The inbox public key of `epoch` with this device's signature (needs the epoch's content key).
    #[wasm_bindgen(js_name = inboxKey)]
    pub fn inbox_key(&self, conversation: &str, epoch: f64) -> JsResult<InboxKey> {
        let (public_key, signature) = self.0.inbox_key(conversation, epoch_from_js(epoch)?).map_err(js_err)?;
        Ok(InboxKey { public_key: public_key.to_vec(), signature: signature.to_vec() })
    }

    /// Opens a sealed webhook message of `epoch`; returns the inner JSON (`unknown_epoch` without the key).
    #[wasm_bindgen(js_name = openSealed)]
    pub fn open_sealed(&self, conversation: &str, epoch: f64, sealed: &[u8]) -> JsResult<String> {
        let plain = self.0.open_sealed(conversation, epoch_from_js(epoch)?, sealed).map_err(js_err)?;
        String::from_utf8(plain.to_vec()).map_err(|_| js_err(CryptoError::DecryptionFailed))
    }

    #[wasm_bindgen(js_name = importEpochKey)]
    pub fn import_epoch_key(&mut self, conversation: &str, epoch: f64, key: &[u8]) -> JsResult<()> {
        self.0.import_epoch_key(conversation, epoch_from_js(epoch)?, &arr(key, "epoch key")?).map_err(js_err)
    }

    #[wasm_bindgen(js_name = knownEpochs)]
    pub fn known_epochs(&self, conversation: &str) -> JsResult<Vec<f64>> {
        self.0.known_epochs(conversation).into_iter().map(epoch_to_js).collect()
    }

    /// Encrypted history backup of one conversation (upload to the home node).
    #[wasm_bindgen(js_name = exportBackup)]
    pub fn export_backup(&self, conversation: &str, backup_key: &[u8]) -> JsResult<Vec<u8>> {
        let key = keys::BackupKey::from_bytes(arr(backup_key, "backup key")?);
        self.0.export_backup(conversation, &key).map_err(js_err)
    }

    /// Imports a history backup; returns the number of epoch keys in it.
    #[wasm_bindgen(js_name = importBackup)]
    pub fn import_backup(&mut self, conversation: &str, backup_key: &[u8], blob: &[u8]) -> JsResult<u32> {
        let key = keys::BackupKey::from_bytes(arr(backup_key, "backup key")?);
        let n = self.0.import_backup(conversation, &key, blob).map_err(js_err)?;
        u32::try_from(n).map_err(|_| js_err(CryptoError::InvalidInput("backup too large")))
    }
}
