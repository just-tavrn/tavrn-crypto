// SPDX-License-Identifier: MPL-2.0
//! Delivery-service checks: the node validating commits and GroupInfos.
#![allow(clippy::expect_used)]

use tavrn_crypto::ds::{DsGroup, group_info_epoch, inspect_key_package};
use tavrn_crypto::{Client, CryptoError, Device};

const CONV: &str = "node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V00";
const ALICE: &str = "alice@node.example";
const BOB: &str = "bob@other.example";
const CAROL: &str = "carol@node.example";
const DEV_A: &str = "01J9ZK3G5M8Q2W4E6R8T0Y2VA1";
const DEV_B: &str = "01J9ZK3G5M8Q2W4E6R8T0Y2VB1";
const DEV_C: &str = "01J9ZK3G5M8Q2W4E6R8T0Y2VC1";

fn client(user: &str, dev: &str) -> Client {
    Client::new(Device::generate(user, dev).expect("device"))
}

/// Alice creates, the node tracks it, Alice adds Bob through the node.
fn setup() -> (DsGroup, Client, Client, Vec<u8>) {
    let mut alice = client(ALICE, DEV_A);
    let mut bob = client(BOB, DEV_B);
    let gi = alice.create_group(CONV).expect("create");
    let mut ds = DsGroup::create(CONV, &gi).expect("ds create");
    assert_eq!(ds.epoch(), 0);
    assert_eq!(group_info_epoch(CONV, &gi).ok(), Some(0));
    let out = alice.add_members(CONV, &[bob.create_key_package().expect("kp")]).expect("add");
    let s = ds.process_commit(&out.commit, &out.group_info).expect("accept add");
    assert_eq!((s.epoch, s.new_epoch), (0, 1));
    assert_eq!(s.committer.identity, format!("{ALICE}/{DEV_A}"));
    assert_eq!(s.committer.signature_key, alice.device().public_key());
    assert!(!s.external_join);
    assert_eq!(s.added.len(), 1);
    assert_eq!(s.added[0].identity, format!("{BOB}/{DEV_B}"));
    assert_eq!(s.added[0].signature_key, bob.device().public_key());
    alice.merge_pending_commit(CONV).expect("merge");
    bob.join_by_welcome(&out.welcome.expect("welcome")).expect("join");
    (ds, alice, bob, out.group_info)
}

#[test]
fn tracks_adds_external_joins_and_removals() {
    let (mut ds, mut alice, mut bob, gi) = setup();
    let mut carol = client(CAROL, DEV_C);
    let join = carol.join_by_external_commit(CONV, &gi).expect("join");
    let s = ds.process_commit(&join.commit, &join.group_info).expect("accept join");
    assert!(s.external_join);
    assert_eq!(s.committer.identity, format!("{CAROL}/{DEV_C}"));
    assert_eq!(s.committer.signature_key, carol.device().public_key());
    assert!(s.added.is_empty() && s.removed.is_empty());
    carol.merge_pending_commit(CONV).expect("merge");
    alice.process_handshake(CONV, &join.commit).expect("alice");
    bob.process_handshake(CONV, &join.commit).expect("bob");

    let rm = alice.remove_members(CONV, &[format!("{BOB}/{DEV_B}")]).expect("remove");
    let s = ds.process_commit(&rm.commit, &rm.group_info).expect("accept remove");
    assert_eq!(s.removed, vec![format!("{BOB}/{DEV_B}")]);
    assert_eq!(ds.epoch(), 3);
    let roster: Vec<String> = ds.roster().expect("roster").into_iter().map(|e| e.identity).collect();
    assert_eq!(roster, vec![format!("{ALICE}/{DEV_A}"), format!("{CAROL}/{DEV_C}")]);
    alice.merge_pending_commit(CONV).expect("merge");
    assert_eq!(roster.len(), alice.roster(CONV).expect("roster").len());

    // The stored GroupInfo is always joinable.
    let mut late = client("dave@node.example", "01J9ZK3G5M8Q2W4E6R8T0Y2VD1");
    let j = late.join_by_external_commit(CONV, &rm.group_info).expect("join");
    ds.process_commit(&j.commit, &j.group_info).expect("accept");
}

#[test]
fn rejoin_reports_the_replaced_leaf() {
    let (mut ds, _alice, bob, gi) = setup();
    let mut again = Client::new(Device::from_secret(BOB, DEV_B, &bob.device().secret()).expect("device"));
    let j = again.join_by_external_commit(CONV, &gi).expect("rejoin");
    let s = ds.process_commit(&j.commit, &j.group_info).expect("accept");
    assert!(s.external_join);
    assert_eq!(s.removed, vec![format!("{BOB}/{DEV_B}")]);
}

#[test]
fn first_commit_wins_and_replays_are_rejected() {
    let (mut ds, mut alice, mut bob, _) = setup();
    let a = alice.self_update(CONV).expect("a");
    let b = bob.self_update(CONV).expect("b");
    ds.process_commit(&a.commit, &a.group_info).expect("first");
    assert_eq!(ds.process_commit(&b.commit, &b.group_info).err(), Some(CryptoError::StaleEpoch));
    assert_eq!(ds.process_commit(&a.commit, &a.group_info).err(), Some(CryptoError::StaleEpoch));
    alice.merge_pending_commit(CONV).expect("merge");
    bob.process_handshake(CONV, &a.commit).expect("bob catches up");
    let c = alice.self_update(CONV).expect("c");
    alice.merge_pending_commit(CONV).expect("merge");
    let d = alice.self_update(CONV).expect("d");
    assert_eq!(ds.process_commit(&d.commit, &d.group_info).err(), Some(CryptoError::FutureEpoch));
    ds.process_commit(&c.commit, &c.group_info).expect("c");
    ds.process_commit(&d.commit, &d.group_info).expect("d");
}

#[test]
fn mismatching_group_info_is_rejected_without_state_change() {
    let (mut ds, mut alice, _bob, old_gi) = setup();
    let up = alice.self_update(CONV).expect("update");
    // GroupInfo of the previous epoch.
    assert!(ds.process_commit(&up.commit, &old_gi).is_err());
    // Tampered GroupInfo.
    let mut bad = up.group_info.clone();
    let n = bad.len();
    bad[n - 5] ^= 1;
    assert!(ds.process_commit(&up.commit, &bad).is_err());
    assert!(ds.process_commit(&up.commit, &[]).is_err());
    assert_eq!(ds.epoch(), 1, "state unchanged");
    ds.process_commit(&up.commit, &up.group_info).expect("valid pair");
    assert_eq!(ds.epoch(), 2);
}

#[test]
fn garbage_and_foreign_messages_are_rejected() {
    let (mut ds, mut alice, _bob, gi) = setup();
    let up = alice.self_update(CONV).expect("update");
    // Layout tail: signature(1+64) || confirmation_tag(1+32) || membership_tag(1+32). The node
    // cannot check the membership tag (members do), but it checks the signature.
    let mut bad = up.commit.clone();
    let n = bad.len();
    bad[n - 66 - 20] ^= 1;
    assert!(ds.process_commit(&bad, &up.group_info).is_err(), "broken signature");
    assert!(ds.process_commit(&gi, &up.group_info).is_err(), "not a commit");
    assert!(ds.process_commit(&[0u8; 3], &up.group_info).is_err());
    let mut other = client(ALICE, DEV_A);
    let foreign_gi = other.create_group("node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V01").expect("create");
    assert_eq!(DsGroup::create(CONV, &foreign_gi).err(), Some(CryptoError::WrongGroup));
    assert!(DsGroup::create("bad", &gi).is_err());
    assert!(DsGroup::create(CONV, &up.commit).is_err());
    assert_eq!(ds.epoch(), 1);
}

#[test]
fn state_roundtrip() {
    let (ds, mut alice, _bob, _) = setup();
    let state = ds.export_state().expect("export");
    let mut restored = DsGroup::import_state(&state).expect("import");
    assert_eq!(restored.conversation(), CONV);
    assert_eq!(restored.epoch(), 1);
    let up = alice.self_update(CONV).expect("update");
    restored.process_commit(&up.commit, &up.group_info).expect("accept");
    assert_eq!(DsGroup::import_state(&state[..10]).err(), Some(CryptoError::StateMalformed));
    assert_eq!(DsGroup::import_state(b"XXXX").err(), Some(CryptoError::StateMalformed));
    let mut extra = state.clone();
    extra.push(1);
    assert_eq!(DsGroup::import_state(&extra).err(), Some(CryptoError::StateMalformed));
}

#[test]
fn key_packages_are_inspected() {
    let bob = client(BOB, DEV_B);
    let kp = bob.create_key_package().expect("kp");
    let e = inspect_key_package(&kp).expect("inspect");
    assert_eq!(e.identity, format!("{BOB}/{DEV_B}"));
    assert_eq!(e.signature_key, bob.device().public_key());
    let mut bad = kp.clone();
    let n = bad.len();
    bad[n - 2] ^= 1;
    assert!(inspect_key_package(&bad).is_err());
    assert!(inspect_key_package(&[]).is_err());
    assert!(group_info_epoch(CONV, &kp).is_err());
}

#[test]
fn a_leaf_with_another_key_is_removed_exactly_and_reported_with_its_key() {
    let (mut ds, mut alice, bob, _) = setup();
    // A second leaf naming Bob's device with a key that is not his (the node's rules would refuse to add it).
    let forged = client(BOB, DEV_B);
    let out = alice.add_members(CONV, &[forged.create_key_package().expect("kp")]).expect("add");
    ds.process_commit(&out.commit, &out.group_info).expect("the DS checks no attestations");
    alice.merge_pending_commit(CONV).expect("merge");
    assert_eq!(
        alice.remove_members(CONV, &[format!("{BOB}/{DEV_B}")]).err(),
        Some(CryptoError::InvalidInput("identity names several leaves; remove them by key")),
        "removal by identity is ambiguous here"
    );
    let leaf =
        tavrn_crypto::RosterEntry { identity: format!("{BOB}/{DEV_B}"), signature_key: forged.device().public_key() };
    let rm = alice.remove_leaves(CONV, std::slice::from_ref(&leaf)).expect("remove");
    let s = ds.process_commit(&rm.commit, &rm.group_info).expect("accepted");
    assert_eq!(s.removed, vec![leaf.identity.clone()]);
    assert_eq!(s.removed_leaves, vec![leaf]);
    alice.merge_pending_commit(CONV).expect("merge");
    let keys: Vec<[u8; 32]> = ds.roster().expect("roster").into_iter().map(|e| e.signature_key).collect();
    assert_eq!(keys, vec![alice.device().public_key(), bob.device().public_key()], "Bob's own leaf stays");
    // Unknown leaves and the own leaf are refused.
    let unknown = tavrn_crypto::RosterEntry { identity: format!("{BOB}/{DEV_B}"), signature_key: [7; 32] };
    assert!(alice.remove_leaves(CONV, &[unknown]).is_err());
    let own =
        tavrn_crypto::RosterEntry { identity: format!("{ALICE}/{DEV_A}"), signature_key: alice.device().public_key() };
    assert!(alice.remove_leaves(CONV, &[own]).is_err());
    assert!(alice.remove_leaves(CONV, &[]).is_err());
}
