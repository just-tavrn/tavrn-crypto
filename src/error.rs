// SPDX-License-Identifier: MPL-2.0
//! Error type of the crate.
//!
//! Messages are short, static descriptions. They never contain key material, plaintext or other
//! secrets, so callers may log them and show them to users.

/// Every fallible function of the crate returns this error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// A parameter is malformed (address, device id, conversation id, base64, length, ...).
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    /// The key file could not be parsed.
    #[error("key file is malformed")]
    KeyFileMalformed,
    /// The key file parsed but its checksum does not match (typo or corruption).
    #[error("key file checksum mismatch")]
    KeyFileChecksum,
    /// The text is a valid key of another kind (a recovery key where the master secret key file
    /// was expected, or the other way round).
    #[error("this is a different kind of key")]
    KeyFileWrongKind,
    /// A versioned format carries a version this build does not understand.
    #[error("unsupported format version")]
    UnsupportedVersion,
    /// A signature did not verify.
    #[error("signature verification failed")]
    BadSignature,
    /// Authenticated decryption failed (wrong key, tampered data or wrong context).
    #[error("decryption failed")]
    DecryptionFailed,
    /// The operating system random number generator failed.
    #[error("random number generator unavailable")]
    Rng,
    /// No MLS group exists locally for the conversation.
    #[error("unknown conversation")]
    UnknownGroup,
    /// An MLS group already exists locally for the conversation.
    #[error("group already exists")]
    GroupExists,
    /// No content key is known for the requested epoch.
    #[error("no content key for this epoch")]
    UnknownEpoch,
    /// The author device is not part of the current MLS roster and no key was supplied.
    #[error("sender device is not a member of the group")]
    UnknownSender,
    /// A handshake message belongs to an epoch that this client already left behind.
    /// Clients ignore these (typically their own, already merged commits).
    #[error("message belongs to an older epoch")]
    StaleEpoch,
    /// A handshake message belongs to a future epoch: earlier commits are missing.
    #[error("message epoch is ahead of the group epoch")]
    FutureEpoch,
    /// A handshake message or GroupInfo belongs to another conversation.
    #[error("message belongs to another conversation")]
    WrongGroup,
    /// The group uses a ciphersuite other than the tavrn ciphersuite.
    #[error("unsupported MLS ciphersuite")]
    WrongCiphersuite,
    /// A member credential is not a well-formed tavrn device credential.
    #[error("invalid member credential")]
    InvalidCredential,
    /// There is no pending commit to merge or discard.
    #[error("no pending commit")]
    NoPendingCommit,
    /// This device is no longer a member of the group.
    #[error("this device was removed from the group")]
    NotMember,
    /// The serialized state is malformed.
    #[error("serialized state is malformed")]
    StateMalformed,
    /// An error reported by OpenMLS. The text is OpenMLS' error description (no key material).
    #[error("MLS error: {0}")]
    Mls(String),
}

impl CryptoError {
    /// Stable machine-readable code (the `name` of the JS error in the WASM build).
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "invalid_input",
            Self::KeyFileMalformed => "key_file_malformed",
            Self::KeyFileChecksum => "key_file_checksum",
            Self::KeyFileWrongKind => "key_file_wrong_kind",
            Self::UnsupportedVersion => "unsupported_version",
            Self::BadSignature => "bad_signature",
            Self::DecryptionFailed => "decryption_failed",
            Self::Rng => "rng",
            Self::UnknownGroup => "unknown_group",
            Self::GroupExists => "group_exists",
            Self::UnknownEpoch => "unknown_epoch",
            Self::UnknownSender => "unknown_sender",
            Self::StaleEpoch => "stale_epoch",
            Self::FutureEpoch => "future_epoch",
            Self::WrongGroup => "wrong_group",
            Self::WrongCiphersuite => "wrong_ciphersuite",
            Self::InvalidCredential => "invalid_credential",
            Self::NoPendingCommit => "no_pending_commit",
            Self::NotMember => "not_member",
            Self::StateMalformed => "state_malformed",
            Self::Mls(_) => "mls",
        }
    }
}

/// Shorthand for results of this crate.
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Converts any OpenMLS error into [`CryptoError::Mls`].
pub(crate) fn mls<E: std::fmt::Display>(e: E) -> CryptoError {
    CryptoError::Mls(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable_and_messages_static() {
        assert_eq!(CryptoError::StaleEpoch.code(), "stale_epoch");
        assert_eq!(CryptoError::InvalidInput("x").code(), "invalid_input");
        assert_eq!(CryptoError::DecryptionFailed.to_string(), "decryption failed");
        assert_eq!(mls("boom"), CryptoError::Mls("boom".into()));
        assert_eq!(mls("boom").code(), "mls");
    }
}
