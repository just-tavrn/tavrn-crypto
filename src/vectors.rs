// SPDX-License-Identifier: MPL-2.0
//! Checks the crate against `protocol/testvectors/encryption.json`, the reference values for
//! other implementations of ENCRYPTION.md.
#![allow(clippy::expect_used)]

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::backup::encrypt_backup_with_nonce;
use crate::content::{content_aad, seal_with_nonce};
use crate::device::Device;
use crate::file::encrypt_file_with;
use crate::identity::{IdentityKey, continuity_message, sign_continuity, wrap_identity_with_nonce};
use crate::keys::{BackupKey, MasterSecret, RecoveryKey, attest_device, attestation_message};
use crate::secret_storage::{
    METHOD_RECOVERY, PRF_INPUT, passkey_method, passkey_wrapping_key, secret_storage_aad, wrap_with_nonce,
};
use crate::util::{b64url_decode_array, b64url_encode};

const VECTORS: &str = include_str!("../protocol/testvectors/encryption.json");

fn seq<const N: usize>(start: u8) -> [u8; N] {
    std::array::from_fn(|i| start.wrapping_add(i as u8))
}

/// Computes all vectors from fixed inputs.
fn compute() -> Value {
    let master = MasterSecret::from_bytes(seq(0));
    let key_file = master.to_key_file("alice@node.example").expect("key file");
    let line = |prefix: &str| key_file.lines().find_map(|l| l.strip_prefix(prefix)).expect("line").to_owned();

    let user = "alice@node.example";
    let device_id = "01J9ZK3G5M8Q2W4E6R8T0Y2VA1";
    let device = Device::from_secret(user, device_id, &seq(32)).expect("device");
    let att = attest_device(&master, user, device_id, &device.public_key()).expect("attest");

    let conversation = "node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V00";
    let content_key: [u8; 32] = seq(64);
    let nonce: [u8; 12] = seq(96);
    let body = r#"{"type":"text","body":"Hello"}"#;
    let content = seal_with_nonce(&content_key, &nonce, conversation, 42, &device, body).expect("seal");

    let backup_key = BackupKey::from_bytes(*master.backup_key().to_bytes());
    let keys = BTreeMap::from([(41u64, seq::<32>(128)), (42u64, content_key)]);
    let backup = encrypt_backup_with_nonce(&backup_key, &nonce, conversation, &keys).expect("backup");

    let file = encrypt_file_with(seq(160), nonce, b"file contents").expect("file");

    let recovery = RecoveryKey::from_bytes(seq(192));
    let recovery_text = recovery.to_text(user).expect("recovery text");
    let recovery_wrap = recovery.wrapping_key();
    let recovery_entry = wrap_with_nonce(&master, &recovery_wrap, &nonce, user, METHOD_RECOVERY).expect("wrap");
    let prf_output: [u8; 32] = seq(224);
    let passkey = passkey_method("Y3JlZGVudGlhbC0x").expect("method");
    let passkey_wrap = passkey_wrapping_key(&prf_output).expect("prf key");
    let passkey_entry = wrap_with_nonce(&master, &passkey_wrap, &nonce, user, &passkey).expect("wrap");

    let rotated = IdentityKey::from_seed(&seq(240));
    let at = "2026-10-06T12:00:00Z";
    let identity_blob = wrap_identity_with_nonce(&master, &rotated, &nonce, user).expect("identity blob");
    let statement = sign_continuity(&IdentityKey::from_master(&master), &rotated, at).expect("continuity");
    let rotated_att = rotated.attest_device(user, device_id, &device.public_key()).expect("attest");

    let inbox_public = crate::sealed::inbox_public_key(&content_key);
    let inbox_message = crate::sealed::inbox_signing_input(conversation, 42, &inbox_public);
    let inbox_payload = r#"{"content":{"type":"text","body":"Deployed"}}"#;
    let mut rng = crate::sealed::FixedRng(seq(248));
    let sealed_box =
        crate::sealed::seal_with_rng(&mut rng, &inbox_public, inbox_payload.as_bytes()).expect("sealed box");

    json!({
        "description": "Reference values for ENCRYPTION.md. Binary values are base64url without padding.",
        "keys": {
            "master_secret": b64url_encode(&seq::<32>(0)),
            "identity_public_key": b64url_encode(&master.identity_public_key()),
            "backup_key": b64url_encode(master.backup_key().to_bytes().as_slice()),
            "key_file_key": line("key: "),
            "key_file_words": line("words: "),
        },
        "device_attestation": {
            "user_address": user,
            "device_id": device_id,
            "device_secret_key": b64url_encode(&seq::<32>(32)),
            "device_public_key": b64url_encode(&device.public_key()),
            "message": b64url_encode(&attestation_message(&device.public_key(), device_id, user)),
            "signature": b64url_encode(&att.signature),
        },
        "content": {
            "conversation": conversation,
            "epoch": 42,
            "author": user,
            "device_id": device_id,
            "content_key": b64url_encode(&content_key),
            "nonce": b64url_encode(&nonce),
            "json": body,
            "aad": b64url_encode(&content_aad(conversation, 42, user, device_id)),
            "content": content,
        },
        "backup": {
            "conversation": conversation,
            "backup_key": b64url_encode(backup_key.to_bytes().as_slice()),
            "nonce": b64url_encode(&nonce),
            "epoch_keys": { "41": b64url_encode(&seq::<32>(128)), "42": b64url_encode(&content_key) },
            "blob": b64url_encode(&backup),
        },
        "secret_storage": {
            "user_address": user,
            "master_secret": b64url_encode(&seq::<32>(0)),
            "nonce": b64url_encode(&nonce),
            "recovery_key": b64url_encode(&seq::<32>(192)),
            "recovery_key_compact": recovery.to_compact(),
            "recovery_key_words": recovery.to_words().expect("words"),
            "recovery_key_text": recovery_text,
            "recovery_wrapping_key": b64url_encode(recovery_wrap.as_slice()),
            "recovery_aad": b64url_encode(&secret_storage_aad(user, METHOD_RECOVERY).expect("aad")),
            "recovery_wrapped": b64url_encode(&recovery_entry),
            "prf_input": b64url_encode(PRF_INPUT),
            "prf_output": b64url_encode(&prf_output),
            "passkey_method": passkey,
            "passkey_wrapping_key": b64url_encode(passkey_wrap.as_slice()),
            "passkey_wrapped": b64url_encode(&passkey_entry),
        },
        "identity_rotation": {
            "user_address": user,
            "master_secret": b64url_encode(&seq::<32>(0)),
            "identity_wrap_key": b64url_encode(master.identity_wrap_key().as_slice()),
            "rotated_seed": b64url_encode(&seq::<32>(240)),
            "rotated_public_key": b64url_encode(&rotated.public_key()),
            "nonce": b64url_encode(&nonce),
            "identity_blob": b64url_encode(&identity_blob),
            "continuity_message": b64url_encode(&continuity_message(&statement.old_key, &statement.new_key, at).expect("msg")),
            "continuity": serde_json::to_value(&statement).expect("json"),
            "device_signature": b64url_encode(&rotated_att.signature),
        },
        "webhook_inbox": {
            "conversation": conversation,
            "epoch": 42,
            "content_key": b64url_encode(&content_key),
            "inbox_secret_key": b64url_encode(crate::sealed::inbox_secret(&content_key).as_slice()),
            "inbox_public_key": b64url_encode(&inbox_public),
            "signature_message": b64url_encode(&inbox_message),
            "device_signature": b64url_encode(&device.sign_raw(&inbox_message)),
            "ephemeral_secret_key": b64url_encode(&seq::<32>(248)),
            "payload": inbox_payload,
            "sealed": b64url_encode(&sealed_box),
        },
        "file": {
            "key": b64url_encode(&seq::<32>(160)),
            "nonce": b64url_encode(&nonce),
            "plaintext": b64url_encode(b"file contents"),
            "ciphertext": b64url_encode(&file.ciphertext),
            "sha256": b64url_encode(&file.sha256),
        },
    })
}

#[test]
fn matches_published_vectors() {
    let expected: Value = serde_json::from_str(VECTORS).expect("vectors JSON");
    let actual = compute();
    if std::env::var_os("TAVRN_PRINT_VECTORS").is_some() {
        println!("{}", serde_json::to_string_pretty(&actual).expect("json"));
    }
    assert_eq!(actual, expected);
}

#[test]
fn published_vectors_decrypt() {
    let v: Value = serde_json::from_str(VECTORS).expect("vectors JSON");
    let s = |path: &[&str]| {
        let mut cur = &v;
        for p in path {
            cur = &cur[*p];
        }
        cur.as_str().expect("string").to_owned()
    };
    let master = MasterSecret::from_key_file(&s(&["keys", "key_file_words"])).expect("words");
    assert_eq!(b64url_encode(&master.identity_public_key()), s(&["keys", "identity_public_key"]));
    let (header, ciphertext) = crate::content::decode(&s(&["content", "content"])).expect("decode");
    let json = crate::content::open(
        &b64url_decode_array(&s(&["content", "content_key"]), "k").expect("key"),
        &s(&["content", "conversation"]),
        &s(&["content", "author"]),
        &s(&["content", "device_id"]),
        &b64url_decode_array(&s(&["device_attestation", "device_public_key"]), "k").expect("key"),
        &header,
        &ciphertext,
    )
    .expect("open");
    assert_eq!(json, s(&["content", "json"]));

    // Secret storage: the recovery key typed as words unlocks the published entry.
    let recovery = RecoveryKey::from_text(&s(&["secret_storage", "recovery_key_words"])).expect("recovery words");
    let entry = crate::util::b64url_decode(&s(&["secret_storage", "recovery_wrapped"])).expect("b64");
    let user = s(&["secret_storage", "user_address"]);
    let unwrapped = crate::secret_storage::unwrap_master_secret(&entry, &recovery.wrapping_key(), &user, "recovery")
        .expect("unwrap recovery");
    assert_eq!(b64url_encode(unwrapped.to_bytes().as_slice()), s(&["secret_storage", "master_secret"]));
    let prf = crate::util::b64url_decode(&s(&["secret_storage", "prf_output"])).expect("b64");
    let entry = crate::util::b64url_decode(&s(&["secret_storage", "passkey_wrapped"])).expect("b64");
    let key = passkey_wrapping_key(&prf).expect("prf key");
    let unwrapped =
        crate::secret_storage::unwrap_master_secret(&entry, &key, &user, &s(&["secret_storage", "passkey_method"]))
            .expect("unwrap passkey");
    assert_eq!(b64url_encode(unwrapped.to_bytes().as_slice()), s(&["secret_storage", "master_secret"]));

    // Identity rotation: the blob unwraps to the rotated key and the published statement verifies.
    let blob = crate::util::b64url_decode(&s(&["identity_rotation", "identity_blob"])).expect("b64");
    let rotated = crate::identity::unwrap_identity_key(&master, &blob, &user).expect("unwrap identity");
    assert_eq!(b64url_encode(&rotated.public_key()), s(&["identity_rotation", "rotated_public_key"]));
    let statement: crate::identity::ContinuityStatement =
        serde_json::from_value(v["identity_rotation"]["continuity"].clone()).expect("statement");
    crate::identity::verify_continuity(&statement).expect("continuity");
    assert_eq!(statement.old_key, s(&["keys", "identity_public_key"]));

    // Write-only webhooks: the published sealed box opens with the key derived from the content key.
    let content_key = b64url_decode_array(&s(&["webhook_inbox", "content_key"]), "k").expect("key");
    let sealed = crate::util::b64url_decode(&s(&["webhook_inbox", "sealed"])).expect("b64");
    let opened = crate::sealed::open(&content_key, &sealed).expect("open sealed");
    assert_eq!(String::from_utf8(opened.to_vec()).expect("utf-8"), s(&["webhook_inbox", "payload"]));
    let device_key = b64url_decode_array(&s(&["device_attestation", "device_public_key"]), "k").expect("key");
    let inbox_key = b64url_decode_array(&s(&["webhook_inbox", "inbox_public_key"]), "k").expect("key");
    let signature = crate::util::b64url_decode(&s(&["webhook_inbox", "device_signature"])).expect("b64");
    crate::sealed::verify_inbox_key(&device_key, &s(&["webhook_inbox", "conversation"]), 42, &inbox_key, &signature)
        .expect("inbox key signature");
}
