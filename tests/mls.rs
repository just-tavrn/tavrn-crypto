// SPDX-License-Identifier: MPL-2.0
//! End-to-end scenarios of the MLS client (several devices, the node simulated in between).
#![allow(clippy::expect_used)]

use tavrn_crypto::{BackupKey, Client, CryptoError, Device, MasterSecret, content_header};

const CONV: &str = "node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V00";
const CONV2: &str = "node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V01";
const ALICE: &str = "alice@node.example";
const BOB: &str = "bob@other.example";
const CAROL: &str = "carol@node.example";
const DEV_A: &str = "01J9ZK3G5M8Q2W4E6R8T0Y2VA1";
const DEV_A2: &str = "01J9ZK3G5M8Q2W4E6R8T0Y2VA2";
const DEV_B: &str = "01J9ZK3G5M8Q2W4E6R8T0Y2VB1";
const DEV_C: &str = "01J9ZK3G5M8Q2W4E6R8T0Y2VC1";
const MSG: &str = r#"{"type":"text","body":"hello"}"#;

fn client(user: &str, dev: &str) -> Client {
    Client::new(Device::generate(user, dev).expect("device"))
}

/// Alice creates the group and adds Bob by KeyPackage; both are at epoch 1.
fn alice_and_bob() -> (Client, Client, Vec<u8>) {
    let mut alice = client(ALICE, DEV_A);
    let mut bob = client(BOB, DEV_B);
    alice.create_group(CONV).expect("create");
    assert_eq!(alice.current_epoch(CONV).ok(), Some(0));
    let kp = bob.create_key_package().expect("kp");
    let out = alice.add_members(CONV, &[kp]).expect("add");
    assert_eq!(out.epoch, 0);
    assert_eq!(alice.merge_pending_commit(CONV).ok(), Some(1));
    let (conv, epoch) = bob.join_by_welcome(&out.welcome.expect("welcome")).expect("welcome join");
    assert_eq!((conv.as_str(), epoch), (CONV, 1));
    (alice, bob, out.group_info)
}

fn send(from: &Client, to: &Client) {
    let c = from.encrypt_content(CONV, MSG).expect("encrypt");
    let d = from.device();
    assert_eq!(to.decrypt_content(CONV, d.user_address(), d.device_id(), &c, None).as_deref(), Ok(MSG));
}

#[test]
fn two_parties_exchange_messages() {
    let (alice, bob, _) = alice_and_bob();
    send(&alice, &bob);
    send(&bob, &alice);
    send(&alice, &alice);
    let roster: Vec<String> = alice.roster(CONV).expect("roster").into_iter().map(|e| e.identity).collect();
    assert_eq!(roster, vec![format!("{ALICE}/{DEV_A}"), format!("{BOB}/{DEV_B}")]);
    assert_eq!(bob.roster(CONV).expect("roster")[0].signature_key, alice.device().public_key());
}

#[test]
fn external_commit_join_and_epoch_rotation() {
    let (mut alice, mut bob, group_info) = alice_and_bob();
    let before = alice.encrypt_content(CONV, MSG).expect("encrypt");

    // Carol joins by herself with the GroupInfo the node stored.
    let mut carol = client(CAROL, DEV_C);
    let out = carol.join_by_external_commit(CONV, &group_info).expect("external join");
    assert_eq!(out.epoch, 1);
    assert!(out.welcome.is_none());
    assert!(carol.encrypt_content(CONV, MSG).is_err(), "no sending before the join is confirmed");
    assert_eq!(carol.merge_pending_commit(CONV).ok(), Some(2));
    for member in [&mut alice, &mut bob] {
        let o = member.process_handshake(CONV, &out.commit).expect("process join");
        assert_eq!(o.epoch, 2);
        assert!(o.external_join);
        assert_eq!(o.committer, format!("{CAROL}/{DEV_C}"));
        assert!(o.added.is_empty() && o.removed.is_empty() && !o.self_removed);
    }
    send(&carol, &alice);
    send(&bob, &carol);
    // Carol joined after the message: she has no key for epoch 1.
    assert_eq!(carol.decrypt_content(CONV, ALICE, DEV_A, &before, None), Err(CryptoError::UnknownEpoch));

    // Epoch key rotation by a self update.
    let k2 = alice.export_epoch_key(CONV, 2).expect("key 2");
    let up = bob.self_update(CONV).expect("update");
    assert_eq!(bob.merge_pending_commit(CONV).ok(), Some(3));
    alice.process_handshake(CONV, &up.commit).expect("process update");
    carol.process_handshake(CONV, &up.commit).expect("process update");
    let k3 = alice.export_epoch_key(CONV, 3).expect("key 3");
    assert_ne!(*k2, *k3);
    assert_eq!(*k3, *carol.export_epoch_key(CONV, 3).expect("key"));
    let after = alice.encrypt_content(CONV, MSG).expect("encrypt");
    assert_eq!(content_header(&after).expect("header").epoch, 3);
    send(&alice, &carol);
    // Old messages stay readable with the stored epoch keys.
    assert_eq!(bob.decrypt_content(CONV, ALICE, DEV_A, &before, None).as_deref(), Ok(MSG));
    // The latest GroupInfo lets a fourth device join at epoch 3.
    let mut alice2 = client(ALICE, DEV_A2);
    let j = alice2.join_by_external_commit(CONV, &up.group_info).expect("join");
    assert_eq!(j.epoch, 3);
}

#[test]
fn removal_cuts_off_future_epochs() {
    let (mut alice, mut bob, _) = alice_and_bob();
    let old = alice.encrypt_content(CONV, MSG).expect("encrypt");
    let out = alice.remove_members(CONV, &[format!("{BOB}/{DEV_B}")]).expect("remove");
    assert!(out.welcome.is_none());
    alice.merge_pending_commit(CONV).expect("merge");
    let o = bob.process_handshake(CONV, &out.commit).expect("process");
    assert!(o.self_removed);
    assert_eq!(o.removed, vec![format!("{BOB}/{DEV_B}")]);
    assert_eq!(bob.encrypt_content(CONV, MSG), Err(CryptoError::NotMember));
    let new = alice.encrypt_content(CONV, MSG).expect("encrypt");
    assert_eq!(bob.decrypt_content(CONV, ALICE, DEV_A, &new, None), Err(CryptoError::UnknownEpoch));
    assert_eq!(bob.decrypt_content(CONV, ALICE, DEV_A, &old, Some(&alice.device().public_key())).as_deref(), Ok(MSG));
    assert_eq!(alice.roster(CONV).expect("roster").len(), 1);
}

#[test]
fn stale_future_and_foreign_commits_are_rejected() {
    let (mut alice, mut bob, _) = alice_and_bob();
    let up1 = alice.self_update(CONV).expect("update");
    alice.merge_pending_commit(CONV).expect("merge");
    let up2 = alice.self_update(CONV).expect("update");
    alice.merge_pending_commit(CONV).expect("merge");
    // Epoch 2's commit before epoch 1's: missing history.
    assert_eq!(bob.process_handshake(CONV, &up2.commit).err(), Some(CryptoError::FutureEpoch));
    bob.process_handshake(CONV, &up1.commit).expect("first");
    // Replay of an applied commit.
    assert_eq!(bob.process_handshake(CONV, &up1.commit).err(), Some(CryptoError::StaleEpoch));
    bob.process_handshake(CONV, &up2.commit).expect("second");
    // Own commit coming back from the log.
    assert_eq!(alice.process_handshake(CONV, &up2.commit).err(), Some(CryptoError::StaleEpoch));
    // A commit of another conversation.
    alice.create_group(CONV2).expect("create");
    assert_eq!(alice.process_handshake(CONV2, &up2.commit).err(), Some(CryptoError::WrongGroup));
    // Tampered commit.
    let up3 = alice.self_update(CONV).expect("update");
    let mut bad = up3.commit.clone();
    let n = bad.len();
    bad[n - 10] ^= 0x55;
    assert!(bob.process_handshake(CONV, &bad).is_err());
    assert_eq!(bob.current_epoch(CONV).ok(), Some(3), "failed processing leaves the state untouched");
    // Non-commit and garbage inputs.
    assert!(bob.process_handshake(CONV, &up3.group_info).is_err());
    assert!(bob.process_handshake(CONV, &[]).is_err());
    assert!(bob.process_handshake(CONV, &[0xff; 64]).is_err());
}

#[test]
fn concurrent_commits_first_wins() {
    let (mut alice, mut bob, _) = alice_and_bob();
    let a = alice.self_update(CONV).expect("alice update");
    let _b = bob.self_update(CONV).expect("bob update");
    // The node accepted Alice's commit; Bob's (same epoch) was rejected.
    alice.merge_pending_commit(CONV).expect("merge");
    let o = bob.process_handshake(CONV, &a.commit).expect("process winner");
    assert!(o.discarded_pending_commit);
    assert_eq!(bob.merge_pending_commit(CONV), Err(CryptoError::NoPendingCommit));
    assert_eq!(bob.current_epoch(CONV).ok(), Some(2));
    send(&alice, &bob);
    // Explicit discard path.
    let _c = bob.self_update(CONV).expect("update");
    bob.discard_pending_commit(CONV).expect("discard");
    assert_eq!(bob.current_epoch(CONV).ok(), Some(2));
    send(&bob, &alice);
}

#[test]
fn rejected_external_join_is_discarded() {
    let (_alice, _bob, gi) = alice_and_bob();
    let mut carol = client(CAROL, DEV_C);
    carol.join_by_external_commit(CONV, &gi).expect("join");
    assert!(carol.has_group(CONV));
    assert!(carol.process_handshake(CONV, &gi).is_err());
    carol.discard_pending_commit(CONV).expect("discard");
    assert!(!carol.has_group(CONV));
    assert_eq!(carol.discard_pending_commit(CONV), Err(CryptoError::UnknownGroup));
}

#[test]
fn rejoin_after_state_loss_replaces_old_leaf() {
    let (mut alice, bob, gi) = alice_and_bob();
    // Bob lost his state but keeps his device key: the external commit removes his old leaf.
    let mut bob_again = Client::new(Device::from_secret(BOB, DEV_B, &bob.device().secret()).expect("device"));
    let out = bob_again.join_by_external_commit(CONV, &gi).expect("rejoin");
    bob_again.merge_pending_commit(CONV).expect("merge");
    let o = alice.process_handshake(CONV, &out.commit).expect("process");
    assert_eq!(o.removed, vec![format!("{BOB}/{DEV_B}")]);
    assert_eq!(alice.roster(CONV).expect("roster").len(), 2);
    send(&bob_again, &alice);
}

#[test]
fn group_info_and_welcome_are_checked() {
    let (alice, _bob, gi) = alice_and_bob();
    let mut carol = client(CAROL, DEV_C);
    assert_eq!(carol.join_by_external_commit(CONV2, &gi).err(), Some(CryptoError::WrongGroup));
    assert!(carol.join_by_external_commit(CONV, &[1, 2, 3]).is_err());
    assert!(carol.join_by_external_commit("bad", &gi).is_err());
    let kp = carol.create_key_package().expect("kp");
    assert!(carol.join_by_external_commit(CONV, &kp).is_err(), "KeyPackage is not a GroupInfo");
    assert!(carol.join_by_welcome(&gi).is_err(), "GroupInfo is not a Welcome");
    assert!(carol.join_by_welcome(&[]).is_err());
    let mut alice = alice;
    assert_eq!(alice.create_group(CONV).err(), Some(CryptoError::GroupExists));
    assert!(alice.add_members(CONV, std::slice::from_ref(&gi)).is_err(), "GroupInfo is not a KeyPackage");
    assert!(alice.add_members(CONV, &[]).is_err());
    assert!(alice.remove_members(CONV, &[format!("{ALICE}/{DEV_A}")]).is_err(), "cannot remove self");
    assert!(alice.remove_members(CONV, &[format!("{CAROL}/{DEV_C}")]).is_err(), "not a member");
    assert_eq!(alice.current_epoch(CONV2).err(), Some(CryptoError::UnknownGroup));
}

#[test]
fn welcome_for_existing_group_is_refused() {
    let (mut alice, mut bob, _) = alice_and_bob();
    let kp = bob.create_key_package().expect("kp");
    // A second Welcome for the same conversation (e.g. a forked group) must not replace state.
    let mut mallory = client("mallory@evil.example", DEV_C);
    mallory.create_group(CONV).expect("fake group with the same id");
    let out = mallory.add_members(CONV, &[kp]).expect("add");
    assert_eq!(bob.join_by_welcome(&out.welcome.expect("welcome")).err(), Some(CryptoError::GroupExists));
    send(&alice, &bob);
    let _ = alice.self_update(CONV).expect("still usable");
}

#[test]
fn key_package_with_foreign_credential_is_rejected() {
    use openmls::prelude::*;
    use openmls_rust_crypto::OpenMlsRustCrypto;

    let (mut alice, _bob, _) = alice_and_bob();
    let provider = OpenMlsRustCrypto::default();
    let signer = Device::generate(CAROL, DEV_C).expect("device");
    let bad = CredentialWithKey {
        credential: BasicCredential::new(b"carol@node.example".to_vec()).into(),
        signature_key: signer.public_key().to_vec().into(),
    };
    let kp = KeyPackage::builder().build(tavrn_crypto::CIPHERSUITE, &provider, &signer, bad).expect("kp");
    let bytes = MlsMessageOut::from(kp.key_package().clone()).to_bytes().expect("bytes");
    assert_eq!(alice.add_members(CONV, &[bytes]).err(), Some(tavrn_crypto::CryptoError::InvalidCredential));
}

#[test]
fn decryption_requires_matching_sender_and_key() {
    let (alice, bob, _) = alice_and_bob();
    let c = alice.encrypt_content(CONV, MSG).expect("encrypt");
    assert_eq!(bob.decrypt_content(CONV, ALICE, DEV_C, &c, None), Err(CryptoError::UnknownSender));
    // Bob claims Alice's message as his own: wrong AAD.
    assert_eq!(bob.decrypt_content(CONV, BOB, DEV_B, &c, None), Err(CryptoError::DecryptionFailed));
    // Wrong explicit key: Alice's leaf carries another one (§3.3).
    assert_eq!(
        bob.decrypt_content(CONV, ALICE, DEV_A, &c, Some(&bob.device().public_key())),
        Err(CryptoError::UnknownSender)
    );
    assert_eq!(bob.decrypt_content(CONV2, ALICE, DEV_A, &c, None), Err(CryptoError::UnknownEpoch));
    assert!(bob.decrypt_content(CONV, ALICE, DEV_A, "%%%", None).is_err());
    assert!(bob.decrypt_content(CONV, "nope", DEV_A, &c, None).is_err());
    assert!(alice.encrypt_content(CONV, "not json").is_err());
    assert_eq!(alice.encrypt_content(CONV2, MSG), Err(CryptoError::UnknownGroup));
}

#[test]
fn state_export_import_roundtrip() {
    let (alice, bob, _) = alice_and_bob();
    let state = bob.export_state().expect("export");
    let mut restored = Client::import_state(&state).expect("import");
    assert_eq!(restored.device().identity(), bob.device().identity());
    assert_eq!(restored.current_epoch(CONV).ok(), Some(1));
    send(&alice, &restored);
    // Restored state keeps working for commits.
    let up = restored.self_update(CONV).expect("update");
    restored.merge_pending_commit(CONV).expect("merge");
    let mut alice = alice;
    alice.process_handshake(CONV, &up.commit).expect("process");
    send(&restored, &alice);

    assert_eq!(Client::import_state(&[]).err(), Some(CryptoError::StateMalformed));
    assert_eq!(Client::import_state(&state[..state.len() - 1]).err(), Some(CryptoError::StateMalformed));
    let mut extra = state.to_vec();
    extra.push(0);
    assert_eq!(Client::import_state(&extra).err(), Some(CryptoError::StateMalformed));
    let mut bad_magic = state.to_vec();
    bad_magic[0] = b'X';
    assert_eq!(Client::import_state(&bad_magic).err(), Some(CryptoError::StateMalformed));
}

/// Rewrites the MLS storage values of an exported state (`TVC1 || str16 || str16 || secret(32) || u32 count ||
/// (u32 key, u32 value)* || rest`): `edit(key, value)` may change each value.
fn rewrite_storage(state: &[u8], edit: impl Fn(&[u8], &mut Vec<u8>)) -> Vec<u8> {
    let u16_at = |i: usize| usize::from(u16::from_be_bytes([state[i], state[i + 1]]));
    let u32_at = |i: usize| u32::from_be_bytes(state[i..i + 4].try_into().expect("u32")) as usize;
    let mut i = 4;
    i += 2 + u16_at(i);
    i += 2 + u16_at(i);
    i += 32;
    let mut out = state[..i].to_vec();
    let count = u32_at(i);
    out.extend_from_slice(&state[i..i + 4]);
    i += 4;
    for _ in 0..count {
        let key = &state[i + 4..i + 4 + u32_at(i)];
        i += 4 + key.len();
        let mut value = state[i + 4..i + 4 + u32_at(i)].to_vec();
        i += 4 + value.len();
        edit(key, &mut value);
        out.extend_from_slice(&u32::try_from(key.len()).expect("len").to_be_bytes());
        out.extend_from_slice(key);
        out.extend_from_slice(&u32::try_from(value.len()).expect("len").to_be_bytes());
        out.extend_from_slice(&value);
    }
    out.extend_from_slice(&state[i..]);
    out
}

#[test]
fn malformed_group_values_are_refused_at_import() {
    let (_, bob, _) = alice_and_bob();
    let state = bob.export_state().expect("export");
    assert_eq!(rewrite_storage(&state, |_, _| {}), state.to_vec(), "the test parser reads the format");
    // Values OpenMLS would read without error handling: a value of another shape, or no JSON at all, used to
    // pass the import and panic on first use (a trap in WebAssembly).
    for (label, value) in [
        (&b"Tree"[..], &b"{}"[..]),
        (b"Tree", b"[1,2"),
        (b"GroupContext", b"null"),
        (b"InterimTranscriptHash", b"{"),
        (b"ConfirmationTag", b"7"),
        (b"GroupState", b"\"x\""),
    ] {
        let broken = rewrite_storage(&state, |k, v| {
            if k.starts_with(label) {
                *v = value.to_vec();
            }
        });
        assert_ne!(broken, state.to_vec(), "{} is in the state", String::from_utf8_lossy(label));
        assert_eq!(
            Client::import_state(&broken).err(),
            Some(CryptoError::StateMalformed),
            "{}",
            String::from_utf8_lossy(label)
        );
    }
    // Values that are not group state still import (they are read with error handling).
    let restored = Client::import_state(&state).expect("import");
    assert!(restored.has_group(CONV));
}

#[test]
fn cached_groups_and_the_exported_state_stay_the_same() {
    let (mut alice, mut bob, _) = alice_and_bob();
    // Every step changes the cached groups; an import of the state exported right after it must equal the client.
    let check = |c: &Client| {
        let restored = Client::import_state(&c.export_state().expect("export")).expect("import");
        assert_eq!(restored.current_epoch(CONV), c.current_epoch(CONV));
        assert_eq!(restored.roster(CONV), c.roster(CONV));
        send(&restored, c);
        send(c, &restored);
    };
    check(&alice);
    check(&bob);
    let up = bob.self_update(CONV).expect("update");
    check(&bob); // pending commit
    bob.merge_pending_commit(CONV).expect("merge");
    alice.process_handshake(CONV, &up.commit).expect("process");
    // A refused (stale) commit leaves the group as it was.
    assert_eq!(alice.process_handshake(CONV, &up.commit).err(), Some(CryptoError::StaleEpoch));
    check(&alice);
    check(&bob);
    let mut carol = client(CAROL, DEV_C);
    alice.add_members(CONV, &[carol.create_key_package().expect("kp")]).expect("add");
    alice.discard_pending_commit(CONV).expect("discard");
    check(&alice);
    assert_eq!(alice.current_epoch(CONV).ok(), Some(2));
    let out2 = alice.add_members(CONV, &[carol.create_key_package().expect("kp")]).expect("add");
    alice.merge_pending_commit(CONV).expect("merge");
    carol.join_by_welcome(&out2.welcome.expect("welcome")).expect("join");
    bob.process_handshake(CONV, &out2.commit).expect("process");
    for c in [&alice, &bob, &carol] {
        check(c);
        assert_eq!(c.roster(CONV).expect("roster").len(), 3);
    }
    alice.delete_group(CONV).expect("delete");
    assert!(!alice.has_group(CONV));
    assert!(!Client::import_state(&alice.export_state().expect("export")).expect("import").has_group(CONV));
}

#[test]
fn an_attested_key_must_match_the_leaf_of_the_device() {
    let (alice, bob, _) = alice_and_bob();
    let c = alice.encrypt_content(CONV, MSG).expect("encrypt");
    let alice_key = alice.device().public_key();
    assert_eq!(bob.decrypt_content(CONV, ALICE, DEV_A, &c, Some(&alice_key)).as_deref(), Ok(MSG));
    // §3.3: the attested key differs from the device's leaf: unknown sender, before the key or signature count.
    let other = client(ALICE, DEV_A).device().public_key();
    assert_eq!(bob.decrypt_content(CONV, ALICE, DEV_A, &c, Some(&other)), Err(CryptoError::UnknownSender));
    let elsewhere = alice.encrypt_content(CONV, MSG).expect("encrypt");
    let mut stranger = client(CAROL, DEV_C);
    // No local group (a history key only): nothing to compare, the signature decides.
    stranger.import_epoch_key(CONV, 1, &bob.export_epoch_key(CONV, 1).expect("key")).expect("import");
    assert_eq!(stranger.decrypt_content(CONV, ALICE, DEV_A, &elsewhere, Some(&alice_key)).as_deref(), Ok(MSG));
    assert_eq!(stranger.decrypt_content(CONV, ALICE, DEV_A, &elsewhere, Some(&other)), Err(CryptoError::BadSignature));
}

#[test]
fn encrypted_content_reports_its_epoch() {
    let (mut alice, mut bob, _) = alice_and_bob();
    let up = alice.self_update(CONV).expect("update");
    alice.merge_pending_commit(CONV).expect("merge");
    bob.process_handshake(CONV, &up.commit).expect("process");
    let (content, epoch) = alice.encrypt_content_with_epoch(CONV, MSG).expect("encrypt");
    assert_eq!(epoch, 2);
    assert_eq!(content_header(&content).expect("header").epoch, epoch);
    assert_eq!(bob.decrypt_content(CONV, ALICE, DEV_A, &content, None).as_deref(), Ok(MSG));
    assert_eq!(alice.encrypt_content_with_epoch(CONV2, MSG).err(), Some(CryptoError::UnknownGroup));
}

#[test]
fn history_backup_restores_old_epochs_on_a_new_device() {
    let master = MasterSecret::generate().expect("master");
    let backup_key = master.backup_key();
    let (mut alice, mut bob, _) = alice_and_bob();
    let m1 = bob.encrypt_content(CONV, MSG).expect("encrypt");
    let up = alice.self_update(CONV).expect("update");
    alice.merge_pending_commit(CONV).expect("merge");
    bob.process_handshake(CONV, &up.commit).expect("process");
    let m2 = bob.encrypt_content(CONV, MSG).expect("encrypt");

    let blob = alice.export_backup(CONV, &backup_key).expect("backup");
    // Alice's new device: no MLS group, but the backup and Bob's attested device key.
    let mut fresh = client(ALICE, DEV_A2);
    assert_eq!(fresh.import_backup(CONV, &backup_key, &blob).ok(), Some(3));
    assert_eq!(fresh.known_epochs(CONV), vec![0, 1, 2]);
    let bob_key = bob.device().public_key();
    assert_eq!(fresh.decrypt_content(CONV, BOB, DEV_B, &m1, Some(&bob_key)).as_deref(), Ok(MSG));
    assert_eq!(fresh.decrypt_content(CONV, BOB, DEV_B, &m2, Some(&bob_key)).as_deref(), Ok(MSG));
    assert_eq!(fresh.decrypt_content(CONV, BOB, DEV_B, &m2, None), Err(CryptoError::UnknownSender));

    let wrong = BackupKey::from_bytes([0u8; 32]);
    assert_eq!(fresh.import_backup(CONV, &wrong, &blob).err(), Some(CryptoError::DecryptionFailed));
    assert_eq!(fresh.import_backup(CONV2, &backup_key, &blob).err(), Some(CryptoError::DecryptionFailed));
    // Importing never overwrites a known key.
    fresh.import_epoch_key(CONV, 1, &[9u8; 32]).expect("import");
    assert_eq!(*fresh.export_epoch_key(CONV, 1).expect("key"), *alice.export_epoch_key(CONV, 1).expect("key"));
    assert_eq!(fresh.export_epoch_key(CONV, 99).err(), Some(CryptoError::UnknownEpoch));
}

#[test]
fn delete_group_keeps_history_keys() {
    let (mut alice, bob, _) = alice_and_bob();
    let c = bob.encrypt_content(CONV, MSG).expect("encrypt");
    alice.delete_group(CONV).expect("delete");
    assert!(!alice.has_group(CONV));
    assert_eq!(alice.decrypt_content(CONV, BOB, DEV_B, &c, Some(&bob.device().public_key())).as_deref(), Ok(MSG));
    assert_eq!(alice.delete_group(CONV), Err(CryptoError::UnknownGroup));
}

#[test]
fn own_commit_from_the_log_is_merged() {
    // The node accepted the commit but its answer was lost; the client sees it in the log.
    let (mut alice, mut bob, _) = alice_and_bob();
    let up = alice.self_update(CONV).expect("update");
    let o = alice.process_handshake(CONV, &up.commit).expect("own commit");
    assert_eq!(o.epoch, 2);
    assert_eq!(o.committer, format!("{ALICE}/{DEV_A}"));
    assert!(!o.discarded_pending_commit);
    assert_eq!(alice.merge_pending_commit(CONV), Err(CryptoError::NoPendingCommit));
    bob.process_handshake(CONV, &up.commit).expect("process");
    send(&alice, &bob);
}

#[test]
fn add_reports_added_identities_to_other_members() {
    let (mut alice, mut bob, _) = alice_and_bob();
    let mut carol = client(CAROL, DEV_C);
    let out = alice.add_members(CONV, &[carol.create_key_package().expect("kp")]).expect("add");
    alice.merge_pending_commit(CONV).expect("merge");
    let o = bob.process_handshake(CONV, &out.commit).expect("process");
    assert_eq!(o.added, vec![format!("{CAROL}/{DEV_C}")]);
    assert!(!o.external_join);
    carol.join_by_welcome(&out.welcome.expect("welcome")).expect("join");
    send(&carol, &bob);
    // A KeyPackage is single-use: the same Welcome cannot be processed twice.
    assert!(carol.join_by_welcome(&[]).is_err());
}

#[test]
fn voice_frame_keys_follow_the_epoch_and_differ_from_content_keys() {
    let (mut alice, mut bob, _) = alice_and_bob();
    let a1 = alice.export_voice_key(CONV, 1).expect("voice key");
    let b1 = bob.export_voice_key(CONV, 1).expect("voice key");
    assert_eq!(*a1, *b1, "every member derives the same frame key");
    assert_ne!(*a1, *alice.export_epoch_key(CONV, 1).expect("content key"), "own exporter label");
    // Only the current epoch can be derived (the exporter secret of older epochs is gone).
    assert_eq!(alice.export_voice_key(CONV, 0).err(), Some(CryptoError::UnknownEpoch));
    assert_eq!(alice.export_voice_key(CONV, 2).err(), Some(CryptoError::UnknownEpoch));
    assert_eq!(alice.export_voice_key(CONV2, 1).err(), Some(CryptoError::UnknownGroup));
    // A new epoch (join, leave, self update) gives a new key.
    let up = bob.self_update(CONV).expect("update");
    bob.merge_pending_commit(CONV).expect("merge");
    alice.process_handshake(CONV, &up.commit).expect("process");
    let a2 = alice.export_voice_key(CONV, 2).expect("voice key 2");
    assert_ne!(*a1, *a2);
    assert_eq!(*a2, *bob.export_voice_key(CONV, 2).expect("voice key 2"));
    // A removed member cannot derive the key of the epoch after its removal.
    let out = alice.remove_members(CONV, &[format!("{BOB}/{DEV_B}")]).expect("remove");
    alice.merge_pending_commit(CONV).expect("merge");
    bob.process_handshake(CONV, &out.commit).expect("process");
    assert!(alice.export_voice_key(CONV, 3).is_ok());
    assert!(bob.export_voice_key(CONV, 3).is_err());
}

#[test]
fn inbox_keys_follow_the_epoch_and_open_sealed_webhook_messages() {
    let (mut alice, mut bob, _) = alice_and_bob();
    let (pk1, sig) = alice.inbox_key(CONV, 1).expect("inbox key");
    assert_eq!(bob.inbox_key(CONV, 1).expect("inbox key").0, pk1, "every member derives the same public key");
    tavrn_crypto::sealed::verify_inbox_key(&alice.device().public_key(), CONV, 1, &pk1, &sig).expect("signed");
    let sealed = tavrn_crypto::sealed::seal(&pk1, MSG.as_bytes()).expect("seal");
    assert_eq!(bob.open_sealed(CONV, 1, &sealed).expect("open").as_slice(), MSG.as_bytes());
    assert_eq!(alice.open_sealed(CONV, 0, &sealed).err(), Some(CryptoError::DecryptionFailed), "wrong epoch");
    assert_eq!(bob.open_sealed(CONV, 7, &sealed).err(), Some(CryptoError::UnknownEpoch));
    // A removed member keeps the old epochs but cannot derive the next pair.
    let out = alice.remove_members(CONV, &[format!("{BOB}/{DEV_B}")]).expect("remove");
    alice.merge_pending_commit(CONV).expect("merge");
    bob.process_handshake(CONV, &out.commit).expect("process");
    let (pk2, _) = alice.inbox_key(CONV, 2).expect("inbox key 2");
    assert_ne!(pk1, pk2);
    assert!(bob.inbox_key(CONV, 2).is_err());
    let later = tavrn_crypto::sealed::seal(&pk2, MSG.as_bytes()).expect("seal");
    assert!(bob.open_sealed(CONV, 2, &later).is_err());
    // The key also comes from a history backup (it is derived from the epoch's content key).
    let backup_key = BackupKey::from_bytes([9u8; 32]);
    let blob = alice.export_backup(CONV, &backup_key).expect("backup");
    let mut fresh = client(ALICE, DEV_A2);
    fresh.import_backup(CONV, &backup_key, &blob).expect("import");
    assert_eq!(fresh.open_sealed(CONV, 2, &later).expect("open").as_slice(), MSG.as_bytes());
}

#[test]
fn history_shares_v2_are_readable_only_by_the_recipient_devices() {
    // ENCRYPTION.md §7b format v2: content format 1 under a fresh key, sealed to the recipient device's share key.
    let (alice, bob, group_info) = alice_and_bob();
    let mut carol = client(CAROL, DEV_C);
    carol.join_by_external_commit(CONV, &group_info).expect("join");
    carol.merge_pending_commit(CONV).expect("merge");
    let payload = r#"{"type":"history_keys","v":2}"#;
    let (content, key) = alice.encrypt_share(CONV, payload).expect("encrypt share");
    // The current epoch goes into the header (the node checks it), but the epoch's content key does not open it.
    assert_eq!(content_header(&content).expect("header").epoch, alice.current_epoch(CONV).expect("epoch"));
    let a = alice.device();
    assert!(carol.decrypt_content(CONV, ALICE, DEV_A, &content, Some(&a.public_key())).is_err(), "not the epoch key");
    let (_, key2) = alice.encrypt_share(CONV, payload).expect("encrypt share");
    assert_ne!(key.as_slice(), key2.as_slice(), "a fresh key per share");
    let sealed = tavrn_crypto::share::seal_share_key(&bob.device().share_public_key(), &key).expect("seal");
    let opened = bob.open_share_box(&sealed).expect("bob opens his box");
    assert_eq!(
        tavrn_crypto::share::decrypt_content_with_key(&opened, CONV, ALICE, DEV_A, &content, &a.public_key())
            .as_deref(),
        Ok(payload)
    );
    assert_eq!(carol.open_share_box(&sealed).map(|_| ()), Err(CryptoError::DecryptionFailed), "carol cannot");
    assert!(alice.encrypt_share(CONV2, payload).is_err(), "no group");
    assert!(alice.encrypt_share(CONV, "[1]").is_err(), "JSON objects only");
}
