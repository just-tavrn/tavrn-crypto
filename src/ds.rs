// SPDX-License-Identifier: MPL-2.0
//! Delivery-service side of the MLS protocol, used by the node (ENCRYPTION.md §4.4).
//!
//! [`DsGroup`] tracks the public state of one conversation's group (ratchet tree, group context)
//! from the GroupInfo of the creator and every accepted commit. [`DsGroup::process_commit`]
//! validates a commit (epoch, signature, membership changes, credentials) together with the
//! GroupInfo of the new epoch and reports who committed, joined and was removed, so the node can
//! apply its authorization rules before storing anything. The state is exported as bytes for
//! the database. Nothing here involves secrets.

use openmls::ciphersuite::signable::Verifiable;
use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::*;
use openmls_rust_crypto::{MemoryStorage, RustCrypto};

use crate::error::{CryptoError, Result, mls};
use crate::mls::{
    CIPHERSUITE, RosterEntry, check_path_leaf_identity, check_proposals, credential_identity, parse_message,
    read_storage, roster_of, signature_key_array, write_storage,
};
use crate::util::{Reader, check_conversation, put_str16};

const STATE_MAGIC: &[u8; 4] = b"TVD1";

/// What a valid commit changes; the node checks this against its permission rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitSummary {
    /// Epoch the commit was created in (the previous current epoch).
    pub epoch: u64,
    /// Epoch after the commit (`epoch + 1`).
    pub new_epoch: u64,
    /// Committing device: identity and leaf signature key (= device public key).
    pub committer: RosterEntry,
    /// The committer joined by external commit.
    pub external_join: bool,
    /// Devices added by KeyPackage.
    pub added: Vec<RosterEntry>,
    /// Identities removed (for an external join: the joiner's own stale leaf, if any).
    pub removed: Vec<String>,
    /// The removed leaves with their signature keys, in the order of `removed`: the node compares the key with
    /// the attested key of the device the leaf names.
    pub removed_leaves: Vec<RosterEntry>,
}

/// Public group state of one conversation as tracked by the node.
pub struct DsGroup {
    conversation: String,
    storage: MemoryStorage,
    group: PublicGroup,
}

impl std::fmt::Debug for DsGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DsGroup").field("conversation", &self.conversation).field("epoch", &self.epoch()).finish()
    }
}

fn parse_group_info(conversation: &str, bytes: &[u8]) -> Result<VerifiableGroupInfo> {
    let MlsMessageBodyIn::GroupInfo(gi) = parse_message(bytes)? else {
        return Err(CryptoError::InvalidInput("not a GroupInfo"));
    };
    if gi.group_id().as_slice() != conversation.as_bytes() {
        return Err(CryptoError::WrongGroup);
    }
    if gi.ciphersuite() != CIPHERSUITE {
        return Err(CryptoError::WrongCiphersuite);
    }
    if gi.extensions().ratchet_tree().is_none() || gi.extensions().external_pub().is_none() {
        return Err(CryptoError::InvalidInput("GroupInfo lacks ratchet tree or external public key"));
    }
    Ok(gi)
}

impl DsGroup {
    /// Starts tracking a conversation from the GroupInfo its creator uploaded.
    pub fn create(conversation: &str, group_info: &[u8]) -> Result<Self> {
        check_conversation(conversation)?;
        let gi = parse_group_info(conversation, group_info)?;
        let tree = gi
            .extensions()
            .ratchet_tree()
            .map(|t| t.ratchet_tree().clone())
            .ok_or(CryptoError::InvalidInput("ratchet tree"))?;
        let storage = MemoryStorage::default();
        let (group, _) = PublicGroup::from_external(&RustCrypto::default(), &storage, tree, gi, ProposalStore::new())
            .map_err(mls)?;
        roster_of(group.members())?;
        Ok(Self { conversation: conversation.to_owned(), storage, group })
    }

    /// Conversation id (`<domain>/<ULID>`).
    pub fn conversation(&self) -> &str {
        &self.conversation
    }

    /// Current epoch.
    pub fn epoch(&self) -> u64 {
        self.group.group_context().epoch().as_u64()
    }

    /// Current member leaves.
    pub fn roster(&self) -> Result<Vec<RosterEntry>> {
        roster_of(self.group.members())
    }

    /// Validates `commit` (must be for the current epoch) and `group_info` (must describe the
    /// resulting epoch, signed by the committer). On success the state advances by one epoch;
    /// on any error it is unchanged.
    pub fn process_commit(&mut self, commit: &[u8], group_info: &[u8]) -> Result<CommitSummary> {
        let MlsMessageBodyIn::PublicMessage(message) = parse_message(commit)? else {
            return Err(CryptoError::InvalidInput("not a public handshake message"));
        };
        let message = ProtocolMessage::from(message);
        if message.group_id().as_slice() != self.conversation.as_bytes() {
            return Err(CryptoError::WrongGroup);
        }
        if message.content_type() != ContentType::Commit {
            return Err(CryptoError::InvalidInput("only commits are accepted"));
        }
        let epoch = self.epoch();
        match message.epoch().as_u64() {
            e if e < epoch => return Err(CryptoError::StaleEpoch),
            e if e > epoch => return Err(CryptoError::FutureEpoch),
            _ => {}
        }
        let crypto = RustCrypto::default();
        let processed = self.group.process_message(&crypto, message).map_err(mls)?;
        let external_join = match processed.sender() {
            Sender::Member(_) => false,
            Sender::NewMemberCommit => true,
            _ => return Err(CryptoError::InvalidInput("unsupported sender")),
        };
        let committer_identity = credential_identity(processed.credential())?;
        let committer_key = match processed.sender() {
            Sender::Member(index) => self.group.leaf(*index).map(|l| l.signature_key().as_slice().to_vec()),
            _ => None,
        };
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(CryptoError::InvalidInput("only commits are accepted"));
        };
        check_proposals(&staged)?;
        if !external_join {
            check_path_leaf_identity(&staged, &committer_identity)?;
        }
        let committer_key = match staged.update_path_leaf_node() {
            Some(leaf) => leaf.signature_key().as_slice().to_vec(),
            None => committer_key.ok_or(CryptoError::InvalidCredential)?,
        };
        let committer =
            RosterEntry { identity: committer_identity, signature_key: signature_key_array(&committer_key)? };
        let mut added = Vec::new();
        for add in staged.add_proposals() {
            let leaf = add.add_proposal().key_package().leaf_node();
            added.push(RosterEntry {
                identity: credential_identity(leaf.credential())?,
                signature_key: signature_key_array(leaf.signature_key().as_slice())?,
            });
        }
        let mut removed_leaves = Vec::new();
        for remove in staged.remove_proposals() {
            let leaf = self.group.leaf(remove.remove_proposal().removed()).ok_or(CryptoError::InvalidCredential)?;
            removed_leaves.push(RosterEntry {
                identity: credential_identity(leaf.credential())?,
                signature_key: signature_key_array(leaf.signature_key().as_slice())?,
            });
        }
        let removed = removed_leaves.iter().map(|e| e.identity.clone()).collect();

        // Apply to a copy, check the new GroupInfo against it, then swap.
        let mut next = self.try_clone()?;
        next.group.merge_commit(&next.storage, *staged).map_err(mls)?;
        next.check_group_info(group_info, &committer.signature_key)?;
        check_unique_keys(&roster_of(next.group.members())?)?;
        *self = next;
        Ok(CommitSummary { epoch, new_epoch: epoch + 1, committer, external_join, added, removed, removed_leaves })
    }

    fn check_group_info(&self, group_info: &[u8], signer_key: &[u8; 32]) -> Result<()> {
        let gi = parse_group_info(&self.conversation, group_info)?;
        let tree = gi.extensions().ratchet_tree().map(|t| t.ratchet_tree().tls_serialize_detached());
        let pk = OpenMlsSignaturePublicKey::new(signer_key.to_vec().into(), SignatureScheme::ED25519).map_err(mls)?;
        let gi = gi.verify(&RustCrypto::default(), &pk).map_err(|_| CryptoError::BadSignature)?;
        if gi.group_context() != self.group.group_context() {
            return Err(CryptoError::InvalidInput("GroupInfo does not match the new epoch"));
        }
        let ours = RatchetTreeIn::from(self.group.export_ratchet_tree()).tls_serialize_detached().map_err(mls)?;
        match tree {
            Some(Ok(t)) if t == ours => Ok(()),
            _ => Err(CryptoError::InvalidInput("GroupInfo ratchet tree does not match")),
        }
    }

    fn try_clone(&self) -> Result<Self> {
        Self::import_state(&self.export_state()?)
    }

    /// Serializes the state for the node's database.
    pub fn export_state(&self) -> Result<Vec<u8>> {
        let mut out = STATE_MAGIC.to_vec();
        put_str16(&mut out, &self.conversation);
        write_storage(&self.storage, &mut out)?;
        Ok(out)
    }

    /// Restores a state from [`DsGroup::export_state`].
    pub fn import_state(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.take(4)? != STATE_MAGIC {
            return Err(CryptoError::StateMalformed);
        }
        let conversation = r.str16()?.to_owned();
        check_conversation(&conversation).map_err(|_| CryptoError::StateMalformed)?;
        let storage = read_storage(&mut r)?;
        r.finish()?;
        let group = PublicGroup::load(&storage, &GroupId::from_slice(conversation.as_bytes()))
            .map_err(|_| CryptoError::StateMalformed)?
            .ok_or(CryptoError::StateMalformed)?;
        Ok(Self { conversation, storage, group })
    }
}

/// No two leaves share a signature key: OpenMLS checks this for Add proposals only, not for the path leaf of an
/// external commit, and a tree with a duplicate key cannot be joined by anyone afterwards.
fn check_unique_keys(roster: &[RosterEntry]) -> Result<()> {
    let mut keys: Vec<&[u8; 32]> = roster.iter().map(|e| &e.signature_key).collect();
    keys.sort_unstable();
    if keys.windows(2).any(|w| w[0] == w[1]) {
        return Err(CryptoError::InvalidCredential);
    }
    Ok(())
}

/// Validates an uploaded KeyPackage and returns its device identity and signature key, so the
/// node can check that it belongs to the uploading device.
pub fn inspect_key_package(bytes: &[u8]) -> Result<RosterEntry> {
    let MlsMessageBodyIn::KeyPackage(kp) = parse_message(bytes)? else {
        return Err(CryptoError::InvalidInput("not a KeyPackage"));
    };
    let kp = kp.validate(&RustCrypto::default(), ProtocolVersion::Mls10).map_err(mls)?;
    if kp.ciphersuite() != CIPHERSUITE {
        return Err(CryptoError::WrongCiphersuite);
    }
    let leaf = kp.leaf_node();
    Ok(RosterEntry {
        identity: credential_identity(leaf.credential())?,
        signature_key: signature_key_array(leaf.signature_key().as_slice())?,
    })
}

/// Epoch of a GroupInfo of `conversation` (unverified; for the node's bookkeeping).
pub fn group_info_epoch(conversation: &str, bytes: &[u8]) -> Result<u64> {
    check_conversation(conversation)?;
    Ok(parse_group_info(conversation, bytes)?.epoch().as_u64())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use crate::{Client, Device};

    const CONV: &str = "node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V00";
    const VICTIM: &str = "victim@node.example/01J9ZK3G5M8Q2W4E6R8T0Y2VV1";

    fn client(user: &str, dev: &str) -> Client {
        Client::new(Device::generate(user, dev).expect("device"))
    }

    /// Alice creates the group, adds Mallory and Bob; the node tracks every step.
    fn group() -> (DsGroup, Client, Client, Client) {
        let mut alice = client("alice@node.example", "01J9ZK3G5M8Q2W4E6R8T0Y2VA1");
        let mut mallory = client("mallory@node.example", "01J9ZK3G5M8Q2W4E6R8T0Y2VM1");
        let mut bob = client("bob@node.example", "01J9ZK3G5M8Q2W4E6R8T0Y2VB1");
        let gi = alice.create_group(CONV).expect("create");
        let mut ds = DsGroup::create(CONV, &gi).expect("ds");
        let kps = [mallory.create_key_package().expect("kp"), bob.create_key_package().expect("kp")];
        let out = alice.add_members(CONV, &kps).expect("add");
        ds.process_commit(&out.commit, &out.group_info).expect("add accepted");
        alice.merge_pending_commit(CONV).expect("merge");
        let welcome = out.welcome.expect("welcome");
        mallory.join_by_welcome(&welcome).expect("mallory joins");
        bob.join_by_welcome(&welcome).expect("bob joins");
        (ds, alice, mallory, bob)
    }

    /// A leaf never changes its identity: a member's self update whose new leaf names another device (with the
    /// committer's own key) is refused by the delivery service and by members, and changes nothing.
    #[test]
    fn member_commit_cannot_change_its_leaf_identity() {
        let (mut ds, _alice, mut mallory, mut bob) = group();
        let up = mallory.self_update_as(CONV, VICTIM).expect("crafted update");
        assert_eq!(ds.process_commit(&up.commit, &up.group_info).err(), Some(CryptoError::InvalidCredential));
        assert_eq!(ds.epoch(), 1, "state unchanged");
        assert_eq!(bob.process_handshake(CONV, &up.commit).err(), Some(CryptoError::InvalidCredential));
        assert_eq!(bob.current_epoch(CONV).ok(), Some(1));
        let roster: Vec<String> = ds.roster().expect("roster").into_iter().map(|e| e.identity).collect();
        assert!(!roster.contains(&VICTIM.to_owned()), "{roster:?}");

        // An honest self update of the same member still goes through, at the DS and at the other members.
        mallory.discard_pending_commit(CONV).expect("discard");
        let up = mallory.self_update(CONV).expect("update");
        ds.process_commit(&up.commit, &up.group_info).expect("accepted");
        bob.process_handshake(CONV, &up.commit).expect("bob follows");
    }

    /// No two leaves share a signature key: an external rejoin that keeps the device's old leaf is refused (such a
    /// tree could not be joined by anyone afterwards); the regular rejoin replaces the old leaf.
    #[test]
    fn external_join_cannot_duplicate_a_signature_key() {
        let (mut ds, mut alice, mallory, bob) = group();
        // A blank leaf left of Bob's: OpenMLS places the joiner there, so the crafted join is well-formed.
        let up = alice.remove_members(CONV, &[mallory.device().identity()]).expect("remove");
        ds.process_commit(&up.commit, &up.group_info).expect("accepted");
        let mut again = Client::new(
            Device::from_secret(bob.device().user_address(), bob.device().device_id(), &bob.device().secret())
                .expect("device"),
        );
        let j = again.join_keeping_old_leaf(CONV, &up.group_info).expect("crafted join");
        assert_eq!(ds.process_commit(&j.commit, &j.group_info).err(), Some(CryptoError::InvalidCredential));
        assert_eq!(ds.epoch(), 2, "state unchanged");
        let j = again.join_by_external_commit(CONV, &up.group_info).expect("join");
        let s = ds.process_commit(&j.commit, &j.group_info).expect("rejoin replaces the old leaf");
        assert_eq!(s.removed, vec![bob.device().identity()]);
        assert_eq!(s.removed_leaves[0].signature_key, bob.device().public_key());
        assert_eq!(ds.roster().expect("roster").len(), 2);
    }
}
