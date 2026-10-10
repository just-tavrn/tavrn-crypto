// SPDX-License-Identifier: MPL-2.0
//! MLS client state of one device (ENCRYPTION.md §4–§7).
//!
//! [`Client`] owns the OpenMLS provider with an in-memory storage that can be exported and
//! imported as one byte string (`export_state` / `import_state`), so the web client can persist
//! it to IndexedDB after every mutating call. The state contains the device secret key, MLS
//! secrets and content keys: it must be stored like a secret.
//!
//! Commits are two-phase: every commit-creating call (`add_members`, `remove_members`,
//! `self_update`, `join_by_external_commit`) leaves a *pending* commit. After the node accepted
//! it, call [`Client::merge_pending_commit`]; after the node rejected it (another commit won the
//! epoch), call [`Client::discard_pending_commit`], process the winning commit and retry.

use std::collections::{BTreeMap, BTreeSet};

use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::OpenMlsProvider;
use zeroize::Zeroizing;

use crate::backup::{decrypt_backup, encrypt_backup};
use crate::content::{self, CONTENT_EXPORTER_LABEL, VOICE_EXPORTER_LABEL};
use crate::device::Device;
use crate::error::{CryptoError, Result, mls};
use crate::keys::BackupKey;
use crate::util::{
    Reader, check_conversation, check_device_id, check_user_address, parse_device_identity, put_bytes32, put_str16,
    random_array,
};

/// The only ciphersuite tavrn v1 uses (`e2ee.mls1`).
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

const STATE_MAGIC: &[u8; 4] = b"TVC1";
const MAX_ENTRIES: usize = 10_000_000;

// ---- Provider ---------------------------------------------------------------------------------

/// OpenMLS provider: RustCrypto + exportable in-memory storage.
#[derive(Default)]
pub(crate) struct Provider {
    crypto: RustCrypto,
    pub(crate) storage: MemoryStorage,
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

pub(crate) fn write_storage(storage: &MemoryStorage, out: &mut Vec<u8>) -> Result<()> {
    let values = storage.values.read().map_err(|_| CryptoError::StateMalformed)?;
    let mut entries: Vec<_> = values.iter().collect();
    entries.sort();
    let count = u32::try_from(entries.len()).map_err(|_| CryptoError::StateMalformed)?;
    out.extend_from_slice(&count.to_be_bytes());
    for (k, v) in entries {
        put_bytes32(out, k)?;
        put_bytes32(out, v)?;
    }
    Ok(())
}

pub(crate) fn read_storage(r: &mut Reader<'_>) -> Result<MemoryStorage> {
    let count = usize::try_from(r.u32()?).map_err(|_| CryptoError::StateMalformed)?;
    if count > MAX_ENTRIES {
        return Err(CryptoError::StateMalformed);
    }
    let mut map = std::collections::HashMap::new();
    for _ in 0..count {
        let k = r.bytes32()?.to_vec();
        let v = r.bytes32()?.to_vec();
        map.insert(k, v);
    }
    let storage = MemoryStorage::default();
    *storage.values.write().map_err(|_| CryptoError::StateMalformed)? = map;
    Ok(storage)
}

// ---- Helpers ----------------------------------------------------------------------------------

pub(crate) fn parse_message(bytes: &[u8]) -> Result<MlsMessageBodyIn> {
    MlsMessageIn::tls_deserialize_exact(bytes)
        .map(MlsMessageIn::extract)
        .map_err(|_| CryptoError::InvalidInput("malformed MLS message"))
}

/// The device identity of a basic credential, checked to be `<user>@<domain>/<device ULID>`.
pub(crate) fn credential_identity(credential: &Credential) -> Result<String> {
    let basic = BasicCredential::try_from(credential.clone()).map_err(|_| CryptoError::InvalidCredential)?;
    let identity = std::str::from_utf8(basic.identity()).map_err(|_| CryptoError::InvalidCredential)?;
    parse_device_identity(identity).ok_or(CryptoError::InvalidCredential)?;
    Ok(identity.to_owned())
}

pub(crate) fn signature_key_array(key: &[u8]) -> Result<[u8; 32]> {
    key.try_into().map_err(|_| CryptoError::InvalidCredential)
}

fn group_id(conversation: &str) -> GroupId {
    GroupId::from_slice(conversation.as_bytes())
}

fn out_bytes(msg: &MlsMessageOut) -> Result<Vec<u8>> {
    msg.to_bytes().map_err(mls)
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build()
}

/// One member leaf of an MLS group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterEntry {
    /// `<username>@<domain>/<device_id>`.
    pub identity: String,
    /// Ed25519 leaf signature key = device public key; must match the device attestation.
    pub signature_key: [u8; 32],
}

pub(crate) fn roster_of<'a>(members: impl Iterator<Item = Member> + 'a) -> Result<Vec<RosterEntry>> {
    members
        .map(|m| {
            Ok(RosterEntry {
                identity: credential_identity(&m.credential)?,
                signature_key: signature_key_array(&m.signature_key)?,
            })
        })
        .collect()
}

type CommitSummary = (Vec<String>, Vec<String>, bool);

/// tavrn v1 commits only carry Add and Remove proposals (plus ExternalInit for external
/// joins) and update paths. Everything else (extension changes, PSKs, ReInit, ...) is refused.
pub(crate) fn check_proposals(staged: &StagedCommit) -> Result<()> {
    for p in staged.queued_proposals() {
        match p.proposal().proposal_type() {
            ProposalType::Add | ProposalType::Remove | ProposalType::ExternalInit => {}
            _ => return Err(CryptoError::InvalidInput("proposal type not allowed")),
        }
    }
    Ok(())
}

/// A leaf never changes its identity (ENCRYPTION.md §4.4): the new leaf of a member's update path must carry the
/// committer's identity, otherwise a member could rename its leaf to another device while keeping its own key.
/// OpenMLS leaves identity continuity to the application (RFC 9420 §5.3.1), so it is checked here.
pub(crate) fn check_path_leaf_identity(staged: &StagedCommit, committer_identity: &str) -> Result<()> {
    match staged.update_path_leaf_node() {
        Some(leaf) if credential_identity(leaf.credential())? != committer_identity => {
            Err(CryptoError::InvalidCredential)
        }
        _ => Ok(()),
    }
}

/// Added and removed identities of a staged commit (evaluated against the pre-commit tree).
fn summarize(group: &MlsGroup, staged: &StagedCommit) -> Result<CommitSummary> {
    check_proposals(staged)?;
    let mut added = Vec::new();
    for add in staged.add_proposals() {
        added.push(credential_identity(add.add_proposal().key_package().leaf_node().credential())?);
    }
    let mut removed = Vec::new();
    for remove in staged.remove_proposals() {
        let index = remove.remove_proposal().removed();
        let member = group.members().find(|m| m.index == index).ok_or(CryptoError::InvalidCredential)?;
        removed.push(credential_identity(&member.credential)?);
    }
    Ok((added, removed, staged.self_removed()))
}

/// Messages produced by a commit-creating call.
#[derive(Debug, Clone)]
pub struct CommitOutput {
    /// MLSMessage (PublicMessage) carrying the commit; `POST …/mls/commits`.
    pub commit: Vec<u8>,
    /// MLSMessage carrying the Welcome for added devices, if any.
    pub welcome: Option<Vec<u8>>,
    /// MLSMessage carrying the GroupInfo of the *new* epoch, with ratchet tree and external
    /// public key, which the node stores for external joins.
    pub group_info: Vec<u8>,
    /// Epoch the commit was created in (the node's current epoch). After merging, the group is
    /// at `epoch + 1`.
    pub epoch: u64,
}

/// Result of processing an incoming commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeOutcome {
    /// Group epoch after the commit.
    pub epoch: u64,
    /// Identity of the committing device.
    pub committer: String,
    /// True for an external commit (the committer joined by itself).
    pub external_join: bool,
    /// Identities added by the commit (via Add proposals).
    pub added: Vec<String>,
    /// Identities removed by the commit.
    pub removed: Vec<String>,
    /// This device was removed; the group is no longer usable for sending.
    pub self_removed: bool,
    /// This device had a pending commit for the same epoch, which is now void: redo it.
    pub discarded_pending_commit: bool,
}

/// MLS client of one device.
pub struct Client {
    provider: Provider,
    device: Device,
    epoch_keys: BTreeMap<(String, u64), Zeroizing<[u8; 32]>>,
    pending_external: BTreeSet<String>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").field("device", &self.device).finish_non_exhaustive()
    }
}

impl Client {
    /// A client with empty state for `device`.
    pub fn new(device: Device) -> Self {
        Self { provider: Provider::default(), device, epoch_keys: BTreeMap::new(), pending_external: BTreeSet::new() }
    }

    /// The device of this client.
    pub fn device(&self) -> &Device {
        &self.device
    }

    // ---- Persistence --------------------------------------------------------------------------

    /// Serializes the complete state (device key, MLS storage, content keys). Secret!
    pub fn export_state(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(Vec::new());
        out.extend_from_slice(STATE_MAGIC);
        put_str16(&mut out, self.device.user_address());
        put_str16(&mut out, self.device.device_id());
        out.extend_from_slice(self.device.secret().as_slice());
        write_storage(&self.provider.storage, &mut out)?;
        let count = u32::try_from(self.epoch_keys.len()).map_err(|_| CryptoError::StateMalformed)?;
        out.extend_from_slice(&count.to_be_bytes());
        for ((conversation, epoch), key) in &self.epoch_keys {
            put_str16(&mut out, conversation);
            out.extend_from_slice(&epoch.to_be_bytes());
            out.extend_from_slice(key.as_slice());
        }
        let count = u32::try_from(self.pending_external.len()).map_err(|_| CryptoError::StateMalformed)?;
        out.extend_from_slice(&count.to_be_bytes());
        for conversation in &self.pending_external {
            put_str16(&mut out, conversation);
        }
        Ok(out)
    }

    /// Restores a client from [`Client::export_state`] output.
    pub fn import_state(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.take(4)? != STATE_MAGIC {
            return Err(CryptoError::StateMalformed);
        }
        let user_address = r.str16()?;
        let device_id = r.str16()?;
        let secret = Zeroizing::new(r.array::<32>()?);
        let device = Device::from_secret(user_address, device_id, &secret).map_err(|_| CryptoError::StateMalformed)?;
        let storage = read_storage(&mut r)?;
        let mut epoch_keys = BTreeMap::new();
        for _ in 0..r.u32()? {
            let conversation = r.str16()?;
            check_conversation(conversation).map_err(|_| CryptoError::StateMalformed)?;
            let epoch = r.u64()?;
            let key = Zeroizing::new(r.array::<32>()?);
            epoch_keys.insert((conversation.to_owned(), epoch), key);
        }
        let mut pending_external = BTreeSet::new();
        for _ in 0..r.u32()? {
            let conversation = r.str16()?;
            check_conversation(conversation).map_err(|_| CryptoError::StateMalformed)?;
            pending_external.insert(conversation.to_owned());
        }
        r.finish()?;
        Ok(Self { provider: Provider { crypto: RustCrypto::default(), storage }, device, epoch_keys, pending_external })
    }

    // ---- Internal helpers ---------------------------------------------------------------------

    fn load(&self, conversation: &str) -> Result<MlsGroup> {
        check_conversation(conversation)?;
        MlsGroup::load(&self.provider.storage, &group_id(conversation)).map_err(mls)?.ok_or(CryptoError::UnknownGroup)
    }

    fn load_ready(&self, conversation: &str) -> Result<MlsGroup> {
        let group = self.load(conversation)?;
        if self.pending_external.contains(conversation) {
            return Err(CryptoError::InvalidInput("external join pending"));
        }
        if !group.is_active() {
            return Err(CryptoError::NotMember);
        }
        Ok(group)
    }

    fn record_epoch_key(&mut self, conversation: &str, group: &MlsGroup) -> Result<()> {
        let key =
            Zeroizing::new(group.export_secret(self.provider.crypto(), CONTENT_EXPORTER_LABEL, &[], 32).map_err(mls)?);
        let key: [u8; 32] = key.as_slice().try_into().map_err(|_| CryptoError::Mls("exporter length".into()))?;
        self.epoch_keys.insert((conversation.to_owned(), group.epoch().as_u64()), Zeroizing::new(key));
        Ok(())
    }

    fn check_group_info(conversation: &str, group_info: &VerifiableGroupInfo) -> Result<()> {
        if group_info.group_id().as_slice() != conversation.as_bytes() {
            return Err(CryptoError::WrongGroup);
        }
        if group_info.ciphersuite() != CIPHERSUITE {
            return Err(CryptoError::WrongCiphersuite);
        }
        Ok(())
    }

    fn delete_local(&mut self, group: &mut MlsGroup) -> Result<()> {
        group.delete(&self.provider.storage).map_err(mls)
    }

    fn finish_commit(bundle: CommitMessageBundle, epoch: u64) -> Result<CommitOutput> {
        let (commit, welcome, group_info) = bundle.into_messages();
        let group_info = group_info.ok_or_else(|| CryptoError::Mls("commit produced no GroupInfo".into()))?;
        Ok(CommitOutput {
            commit: out_bytes(&commit)?,
            welcome: welcome.as_ref().map(out_bytes).transpose()?,
            group_info: out_bytes(&group_info)?,
            epoch,
        })
    }

    // ---- Key packages and groups --------------------------------------------------------------

    /// Creates a single-use KeyPackage (MLSMessage bytes) to upload to the home node.
    pub fn create_key_package(&self) -> Result<Vec<u8>> {
        let bundle = KeyPackage::builder()
            .build(CIPHERSUITE, &self.provider, &self.device, self.device.credential_with_key())
            .map_err(mls)?;
        out_bytes(&MlsMessageOut::from(bundle.key_package().clone()))
    }

    /// True if a local group exists for `conversation`.
    pub fn has_group(&self, conversation: &str) -> bool {
        self.load(conversation).is_ok()
    }

    /// Creates the MLS group of a new conversation (epoch 0, this device the only member).
    /// Returns the GroupInfo (MLSMessage) to upload as the conversation's first GroupInfo.
    pub fn create_group(&mut self, conversation: &str) -> Result<Vec<u8>> {
        check_conversation(conversation)?;
        if self.has_group(conversation) {
            return Err(CryptoError::GroupExists);
        }
        let group = MlsGroup::builder()
            .with_group_id(group_id(conversation))
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .build(&self.provider, &self.device, self.device.credential_with_key())
            .map_err(mls)?;
        self.record_epoch_key(conversation, &group)?;
        let group_info = group.export_group_info(self.provider.crypto(), &self.device, true).map_err(mls)?;
        out_bytes(&group_info)
    }

    /// Joins `conversation` with an external commit built from the node's GroupInfo.
    ///
    /// Replaces any local state of the conversation. The commit stays pending until
    /// [`Client::merge_pending_commit`] (node accepted) or [`Client::discard_pending_commit`].
    pub fn join_by_external_commit(&mut self, conversation: &str, group_info: &[u8]) -> Result<CommitOutput> {
        self.external_join(conversation, group_info, |_| true)
    }

    /// Test helper: an external join that leaves this device's old leaf in the group (drops the Remove OpenMLS
    /// adds for a leaf with the same signature key), i.e. a join that would duplicate the key.
    #[cfg(test)]
    pub(crate) fn join_keeping_old_leaf(&mut self, conversation: &str, group_info: &[u8]) -> Result<CommitOutput> {
        self.external_join(conversation, group_info, |p| p.proposal().proposal_type() != ProposalType::Remove)
    }

    fn external_join(
        &mut self,
        conversation: &str,
        group_info: &[u8],
        proposals: impl FnMut(&QueuedProposal) -> bool,
    ) -> Result<CommitOutput> {
        check_conversation(conversation)?;
        let MlsMessageBodyIn::GroupInfo(group_info) = parse_message(group_info)? else {
            return Err(CryptoError::InvalidInput("not a GroupInfo"));
        };
        Self::check_group_info(conversation, &group_info)?;
        let epoch = group_info.epoch().as_u64();
        if let Ok(mut old) = self.load(conversation) {
            self.delete_local(&mut old)?;
        }
        self.pending_external.remove(conversation);
        let (mut group, bundle) = MlsGroup::external_commit_builder()
            .with_config(join_config())
            .skip_lifetime_validation()
            .build_group(&self.provider, group_info, self.device.credential_with_key())
            .map_err(mls)?
            .load_psks(self.provider.storage())
            .map_err(mls)?
            .build(self.provider.rand(), self.provider.crypto(), &self.device, proposals)
            .map_err(mls)?
            .finalize(&self.provider)
            .map_err(mls)?;
        if let Err(e) = roster_of(group.members()) {
            self.delete_local(&mut group)?;
            return Err(e);
        }
        self.pending_external.insert(conversation.to_owned());
        Self::finish_commit(bundle, epoch)
    }

    /// Joins a group from a Welcome (after another member added this device).
    /// Returns the conversation id (the MLS group id) and the epoch.
    pub fn join_by_welcome(&mut self, welcome: &[u8]) -> Result<(String, u64)> {
        let MlsMessageBodyIn::Welcome(welcome) = parse_message(welcome)? else {
            return Err(CryptoError::InvalidInput("not a Welcome"));
        };
        if welcome.ciphersuite() != CIPHERSUITE {
            return Err(CryptoError::WrongCiphersuite);
        }
        let builder = StagedWelcome::build_from_welcome(&self.provider, &join_config(), welcome).map_err(mls)?;
        let conversation =
            std::str::from_utf8(builder.processed_welcome().unverified_group_info().group_id().as_slice())
                .ok()
                .filter(|c| crate::util::valid_conversation(c))
                .map(str::to_owned)
                .ok_or(CryptoError::InvalidInput("group id is not a conversation id"))?;
        if self.has_group(&conversation) {
            return Err(CryptoError::GroupExists);
        }
        let staged = builder.skip_lifetime_validation().build().map_err(mls)?;
        if staged.group_context().group_id().as_slice() != conversation.as_bytes() {
            return Err(CryptoError::WrongGroup);
        }
        roster_of(staged.members())?;
        let group = staged.into_group(&self.provider).map_err(mls)?;
        self.record_epoch_key(&conversation, &group)?;
        Ok((conversation, group.epoch().as_u64()))
    }

    /// Adds devices by their KeyPackages (MLSMessage bytes) with a commit that also updates
    /// this device's leaf (post-compromise security).
    pub fn add_members(&mut self, conversation: &str, key_packages: &[Vec<u8>]) -> Result<CommitOutput> {
        if key_packages.is_empty() {
            return Err(CryptoError::InvalidInput("no key packages"));
        }
        let mut group = self.load_ready(conversation)?;
        let mut validated = Vec::with_capacity(key_packages.len());
        for kp in key_packages {
            let MlsMessageBodyIn::KeyPackage(kp) = parse_message(kp)? else {
                return Err(CryptoError::InvalidInput("not a KeyPackage"));
            };
            let kp = kp.validate(self.provider.crypto(), ProtocolVersion::Mls10).map_err(mls)?;
            if kp.ciphersuite() != CIPHERSUITE {
                return Err(CryptoError::WrongCiphersuite);
            }
            credential_identity(kp.leaf_node().credential())?;
            validated.push(kp);
        }
        let epoch = group.epoch().as_u64();
        let bundle = group
            .commit_builder()
            .propose_adds(validated)
            .force_self_update(true)
            .load_psks(self.provider.storage())
            .map_err(mls)?
            .build(self.provider.rand(), self.provider.crypto(), &self.device, |_| true)
            .map_err(mls)?
            .stage_commit(&self.provider)
            .map_err(mls)?;
        Self::finish_commit(bundle, epoch)
    }

    /// Removes devices (by identity `<user>@<domain>/<device>`) from the group.
    pub fn remove_members(&mut self, conversation: &str, identities: &[String]) -> Result<CommitOutput> {
        self.remove_where(conversation, identities.len(), |m, i| {
            credential_identity(&m.credential).is_ok_and(|id| id == identities[i])
        })
    }

    /// Removes leaves by identity *and* signature key. Unlike [`Client::remove_members`] this picks exactly the
    /// given leaf when two leaves name the same device, e.g. a leaf whose key is not the device's attested key.
    pub fn remove_leaves(&mut self, conversation: &str, leaves: &[RosterEntry]) -> Result<CommitOutput> {
        self.remove_where(conversation, leaves.len(), |m, i| {
            m.signature_key == leaves[i].signature_key
                && credential_identity(&m.credential).is_ok_and(|id| id == leaves[i].identity)
        })
    }

    /// Commits the removal of one leaf per target `0..count`, the first member matching `matches(member, i)`.
    fn remove_where(
        &mut self,
        conversation: &str,
        count: usize,
        matches: impl Fn(&Member, usize) -> bool,
    ) -> Result<CommitOutput> {
        if count == 0 {
            return Err(CryptoError::InvalidInput("no identities"));
        }
        let mut group = self.load_ready(conversation)?;
        let own = group.own_leaf_index();
        let mut indices = Vec::with_capacity(count);
        for i in 0..count {
            let index = group
                .members()
                .find(|m| matches(m, i))
                .map(|m| m.index)
                .ok_or(CryptoError::InvalidInput("identity is not a member"))?;
            if index == own {
                return Err(CryptoError::InvalidInput("cannot remove own device"));
            }
            indices.push(index);
        }
        let epoch = group.epoch().as_u64();
        let bundle = group
            .commit_builder()
            .propose_removals(indices)
            .load_psks(self.provider.storage())
            .map_err(mls)?
            .build(self.provider.rand(), self.provider.crypto(), &self.device, |_| true)
            .map_err(mls)?
            .stage_commit(&self.provider)
            .map_err(mls)?;
        Self::finish_commit(bundle, epoch)
    }

    /// Commits a fresh leaf for this device: rotates the epoch (and the content key).
    pub fn self_update(&mut self, conversation: &str) -> Result<CommitOutput> {
        let mut group = self.load_ready(conversation)?;
        let epoch = group.epoch().as_u64();
        let bundle = group
            .commit_builder()
            .force_self_update(true)
            .load_psks(self.provider.storage())
            .map_err(mls)?
            .build(self.provider.rand(), self.provider.crypto(), &self.device, |_| true)
            .map_err(mls)?
            .stage_commit(&self.provider)
            .map_err(mls)?;
        Self::finish_commit(bundle, epoch)
    }

    /// Test helper: a self update whose new leaf carries `identity` in its credential (keeping this device's
    /// signature key), i.e. a commit that tries to change the identity of the committer's leaf.
    #[cfg(test)]
    pub(crate) fn self_update_as(&mut self, conversation: &str, identity: &str) -> Result<CommitOutput> {
        let mut group = self.load_ready(conversation)?;
        let epoch = group.epoch().as_u64();
        let credential_with_key = CredentialWithKey {
            credential: BasicCredential::new(identity.as_bytes().to_vec()).into(),
            signature_key: self.device.public_key().to_vec().into(),
        };
        let bundle = group
            .commit_builder()
            .force_self_update(true)
            .leaf_node_parameters(LeafNodeParameters::builder().with_credential_with_key(credential_with_key).build())
            .load_psks(self.provider.storage())
            .map_err(mls)?
            .build(self.provider.rand(), self.provider.crypto(), &self.device, |_| true)
            .map_err(mls)?
            .stage_commit(&self.provider)
            .map_err(mls)?;
        Self::finish_commit(bundle, epoch)
    }

    /// Applies this device's pending commit after the node accepted it. Returns the new epoch.
    pub fn merge_pending_commit(&mut self, conversation: &str) -> Result<u64> {
        let mut group = self.load(conversation)?;
        if self.pending_external.remove(conversation) {
            // OpenMLS applies an external commit when creating it; only the confirmation is left.
            self.record_epoch_key(conversation, &group)?;
            return Ok(group.epoch().as_u64());
        }
        if group.pending_commit().is_none() {
            return Err(CryptoError::NoPendingCommit);
        }
        group.merge_pending_commit(&self.provider).map_err(mls)?;
        self.record_epoch_key(conversation, &group)?;
        Ok(group.epoch().as_u64())
    }

    /// Drops this device's pending commit after the node rejected it. A rejected external join
    /// deletes the local group (join again with a fresh GroupInfo).
    pub fn discard_pending_commit(&mut self, conversation: &str) -> Result<()> {
        let mut group = self.load(conversation)?;
        if self.pending_external.remove(conversation) {
            return self.delete_local(&mut group);
        }
        if group.pending_commit().is_none() {
            return Err(CryptoError::NoPendingCommit);
        }
        group.clear_pending_commit(&self.provider.storage).map_err(mls)
    }

    /// Processes a commit from the node's handshake log (in epoch order).
    ///
    /// Returns [`CryptoError::StaleEpoch`] for commits of past epochs (e.g. this device's own,
    /// already merged commit); callers skip those. [`CryptoError::FutureEpoch`] means earlier
    /// commits are missing: fetch them first.
    pub fn process_handshake(&mut self, conversation: &str, message: &[u8]) -> Result<HandshakeOutcome> {
        let mut group = self.load(conversation)?;
        if self.pending_external.contains(conversation) {
            return Err(CryptoError::InvalidInput("external join pending"));
        }
        if !group.is_active() {
            return Err(CryptoError::NotMember);
        }
        let message = match parse_message(message)? {
            MlsMessageBodyIn::PublicMessage(m) => ProtocolMessage::from(m),
            _ => return Err(CryptoError::InvalidInput("not a public handshake message")),
        };
        if message.group_id().as_slice() != conversation.as_bytes() {
            return Err(CryptoError::WrongGroup);
        }
        let epoch = message.epoch().as_u64();
        let current = group.epoch().as_u64();
        if epoch < current {
            return Err(CryptoError::StaleEpoch);
        }
        if epoch > current {
            return Err(CryptoError::FutureEpoch);
        }
        let had_pending = group.pending_commit().is_some();
        let processed = group.process_message(&self.provider, message).map_err(mls)?;
        let external_join = matches!(processed.sender(), Sender::NewMemberCommit);
        let from_member = matches!(processed.sender(), Sender::Member(_));
        let committer = credential_identity(processed.credential())?;
        let (summary, own) = match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                if from_member {
                    check_path_leaf_identity(&staged, &committer)?;
                }
                let summary = summarize(&group, &staged)?;
                group.merge_staged_commit(&self.provider, *staged).map_err(mls)?;
                (summary, false)
            }
            // This device's own commit came back from the log (e.g. the node's answer to the
            // POST was lost): it was accepted, so merge it.
            ProcessedMessageContent::OwnPendingCommit => {
                let staged = group.pending_commit().ok_or(CryptoError::NoPendingCommit)?;
                let summary = summarize(&group, staged)?;
                group.merge_pending_commit(&self.provider).map_err(mls)?;
                (summary, true)
            }
            _ => return Err(CryptoError::InvalidInput("only commits are supported")),
        };
        let (added, removed, self_removed) = summary;
        if !self_removed {
            self.record_epoch_key(conversation, &group)?;
        }
        Ok(HandshakeOutcome {
            epoch: group.epoch().as_u64(),
            committer,
            external_join,
            added,
            removed,
            self_removed,
            discarded_pending_commit: had_pending && !own,
        })
    }

    /// Current epoch of the local group.
    pub fn current_epoch(&self, conversation: &str) -> Result<u64> {
        Ok(self.load(conversation)?.epoch().as_u64())
    }

    /// All member leaves of the local group (compare against the node's member list and the
    /// device attestations to detect ghost members).
    pub fn roster(&self, conversation: &str) -> Result<Vec<RosterEntry>> {
        roster_of(self.load(conversation)?.members())
    }

    /// Deletes the local group state (content keys are kept for history).
    pub fn delete_group(&mut self, conversation: &str) -> Result<()> {
        let mut group = self.load(conversation)?;
        self.pending_external.remove(conversation);
        self.delete_local(&mut group)
    }

    // ---- Content ------------------------------------------------------------------------------

    /// Encrypts and signs a JSON content object for the current epoch. Returns the base64url
    /// `content` field; its epoch is also the envelope's `epoch`.
    pub fn encrypt_content(&self, conversation: &str, json: &str) -> Result<String> {
        let group = self.load_ready(conversation)?;
        let epoch = group.epoch().as_u64();
        let key = self.epoch_keys.get(&(conversation.to_owned(), epoch)).ok_or(CryptoError::UnknownEpoch)?;
        content::seal(key, conversation, epoch, &self.device, json)
    }

    /// Decrypts `content` written by `author`/`device_id` and verifies its device signature.
    ///
    /// Without `device_public_key` the key is taken from the current MLS roster (the leaf of
    /// `<author>/<device_id>`); if that device is no longer a member, the caller supplies the key
    /// from the device's verified attestation.
    pub fn decrypt_content(
        &self,
        conversation: &str,
        author: &str,
        device_id: &str,
        content: &str,
        device_public_key: Option<&[u8; 32]>,
    ) -> Result<String> {
        check_conversation(conversation)?;
        check_user_address(author)?;
        check_device_id(device_id)?;
        let (header, ciphertext) = content::decode(content)?;
        let key = self.epoch_keys.get(&(conversation.to_owned(), header.epoch)).ok_or(CryptoError::UnknownEpoch)?;
        let device_key = match device_public_key {
            Some(k) => *k,
            None => {
                let identity = format!("{author}/{device_id}");
                self.roster(conversation)
                    .map_err(|_| CryptoError::UnknownSender)?
                    .into_iter()
                    .find(|e| e.identity == identity)
                    .map(|e| e.signature_key)
                    .ok_or(CryptoError::UnknownSender)?
            }
        };
        content::open(key, conversation, author, device_id, &device_key, &header, &ciphertext)
    }

    /// A history share v2 (`ENCRYPTION.md` §7b): encrypts and signs `json` like content of the current epoch, but
    /// under a fresh random key, which the caller seals to every recipient device
    /// ([`crate::share::seal_share_key`]). Returns the base64url content and the key.
    pub fn encrypt_share(&self, conversation: &str, json: &str) -> Result<(String, Zeroizing<[u8; 32]>)> {
        let group = self.load_ready(conversation)?;
        let key = Zeroizing::new(random_array::<32>()?);
        let content = content::seal(&key, conversation, group.epoch().as_u64(), &self.device, json)?;
        Ok((content, key))
    }

    /// Opens a sealed share key addressed to this device (its share key, `ENCRYPTION.md` §3.1).
    pub fn open_share_box(&self, sealed: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        crate::share::open_share_box(&self.device.share_secret(), sealed)
    }

    // ---- Epoch keys and backup ----------------------------------------------------------------

    /// The content key of `epoch`, if known.
    pub fn export_epoch_key(&self, conversation: &str, epoch: u64) -> Result<Zeroizing<[u8; 32]>> {
        check_conversation(conversation)?;
        self.epoch_keys.get(&(conversation.to_owned(), epoch)).cloned().ok_or(CryptoError::UnknownEpoch)
    }

    /// The voice frame key of the current epoch (`ENCRYPTION.md` §5a):
    /// `MLS-Exporter("tavrn voice frame v1", "", 32)`. Only the current epoch can be derived; clients
    /// derive it on every epoch change while they are in voice and keep the previous ones in the key ring
    /// of their media encryption. `UnknownEpoch` if `epoch` is not the current one.
    pub fn export_voice_key(&self, conversation: &str, epoch: u64) -> Result<Zeroizing<[u8; 32]>> {
        let group = self.load_ready(conversation)?;
        if group.epoch().as_u64() != epoch {
            return Err(CryptoError::UnknownEpoch);
        }
        let key =
            Zeroizing::new(group.export_secret(self.provider.crypto(), VOICE_EXPORTER_LABEL, &[], 32).map_err(mls)?);
        let key: [u8; 32] = key.as_slice().try_into().map_err(|_| CryptoError::Mls("exporter length".into()))?;
        Ok(Zeroizing::new(key))
    }

    /// The inbox public key of `epoch` for write-only webhooks with this device's signature over it
    /// (`ENCRYPTION.md` §5b), for `PUT …/inbox-key`. Needs the epoch's content key.
    pub fn inbox_key(&self, conversation: &str, epoch: u64) -> Result<([u8; 32], [u8; 64])> {
        let key = self.export_epoch_key(conversation, epoch)?;
        let public_key = crate::sealed::inbox_public_key(&key);
        let signature = self.device.sign_raw(&crate::sealed::inbox_signing_input(conversation, epoch, &public_key));
        Ok((public_key, signature))
    }

    /// Opens a sealed webhook message of `epoch` (`ENCRYPTION.md` §5b); the result is the inner JSON payload.
    /// `UnknownEpoch` without the epoch's content key (current state, backup or history share).
    pub fn open_sealed(&self, conversation: &str, epoch: u64, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let key = self.export_epoch_key(conversation, epoch)?;
        crate::sealed::open(&key, sealed)
    }

    /// Stores a content key (from a backup). An already known key for the epoch is kept.
    pub fn import_epoch_key(&mut self, conversation: &str, epoch: u64, key: &[u8; 32]) -> Result<()> {
        check_conversation(conversation)?;
        self.epoch_keys.entry((conversation.to_owned(), epoch)).or_insert_with(|| Zeroizing::new(*key));
        Ok(())
    }

    /// Epochs with a known content key for `conversation`.
    pub fn known_epochs(&self, conversation: &str) -> Vec<u64> {
        self.epoch_keys.keys().filter(|(c, _)| c == conversation).map(|(_, e)| *e).collect()
    }

    /// Encrypts all known content keys of `conversation` for the history backup.
    pub fn export_backup(&self, conversation: &str, backup_key: &BackupKey) -> Result<Vec<u8>> {
        check_conversation(conversation)?;
        let keys: Zeroizing<Vec<(u64, [u8; 32])>> = Zeroizing::new(
            self.epoch_keys.iter().filter(|((c, _), _)| c == conversation).map(|((_, e), k)| (*e, **k)).collect(),
        );
        let map = keys.iter().copied().collect::<BTreeMap<_, _>>();
        let blob = encrypt_backup(backup_key, conversation, &map);
        for (_, mut k) in map {
            zeroize::Zeroize::zeroize(&mut k);
        }
        blob
    }

    /// Imports a history backup of `conversation`. Returns the number of keys in the backup.
    pub fn import_backup(&mut self, conversation: &str, backup_key: &BackupKey, blob: &[u8]) -> Result<usize> {
        let keys = decrypt_backup(backup_key, conversation, blob)?;
        let n = keys.len();
        for (epoch, key) in keys {
            self.import_epoch_key(conversation, epoch, &key)?;
        }
        Ok(n)
    }
}
