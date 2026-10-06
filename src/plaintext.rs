// SPDX-License-Identifier: MPL-2.0
//! Device signatures on plaintext messages (FEDERATION.md §10.3).
//!
//! Messages in unencrypted channels are otherwise authenticated only by the session, so the hosting
//! node could forge them. The author's device signs the envelope fields the node must not change and
//! the content object in its RFC 8785 (JCS) form:
//!
//! ```text
//! signed    = "tavrn plaintext signature v1" || 0x00
//!             || str16(conversation) || str16(author) || str16(device_id)
//!             || str16(reply_to or "") || str16(thread_id or "")
//!             || u8(mentions_everyone) || u16(n) || str16(mention_1) || … || str16(mention_n)
//!             || u16(m) || ( str16(attachment id) || u64(size) || str16(sha256) ) for each attachment
//!             || nonce(16) || u32(len(content)) || content
//! signature = base64url( nonce(16) || Ed25519-Sign(device key, signed) )
//! ```

use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;

use crate::device::Device;
use crate::error::{CryptoError, Result};
use crate::util::{
    b64url_decode, b64url_encode, check_conversation, check_device_id, check_user_address, put_bytes32, put_str16,
    random_array, valid_ulid,
};

/// Domain separation prefix of the plaintext signature.
pub const PLAINTEXT_SIGNATURE_CONTEXT: &[u8] = b"tavrn plaintext signature v1\0";
/// Length of the decoded `signature` envelope field: nonce (16) and Ed25519 signature (64).
pub const PLAINTEXT_SIGNATURE_LEN: usize = 16 + 64;
/// Client capability that makes signing mandatory (FEDERATION.md §12).
pub const SIGNED_CAPABILITY: &str = "content.signed1";
/// Upper bounds of the signed lists (the node allows far fewer; these only keep the encoding sound).
const MAX_MENTIONS: usize = 1000;
const MAX_ATTACHMENTS: usize = 100;
/// Longest attachment hash accepted (base64url of SHA-256 is 43 characters).
const MAX_SHA256_LEN: usize = 128;

/// One attachment as listed in the envelope (blob id, size, hash).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlaintextAttachment {
    /// Blob id (ULID).
    pub id: String,
    /// Size in bytes as stored by the node.
    pub size: u64,
    /// base64url SHA-256 of the blob as stored by the node.
    pub sha256: String,
}

/// The envelope fields covered by the signature (FEDERATION.md §10.3), in envelope form.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlaintextFields {
    /// Qualified conversation id `<node domain>/<conversation ULID>`.
    pub conversation: String,
    /// Author address `<username>@<domain>`.
    pub author: String,
    /// Sending (or last editing) device.
    pub device_id: String,
    /// Envelope `reply_to_id`.
    #[serde(default)]
    pub reply_to: Option<String>,
    /// Envelope `thread_id`.
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub mentions_everyone: bool,
    /// Envelope `mentions` in envelope order.
    #[serde(default)]
    pub mentions: Vec<String>,
    /// Envelope `attachments` in envelope order.
    #[serde(default)]
    pub attachments: Vec<PlaintextAttachment>,
}

impl PlaintextFields {
    fn validate(&self) -> Result<()> {
        check_conversation(&self.conversation)?;
        check_user_address(&self.author)?;
        check_device_id(&self.device_id)?;
        for id in [&self.reply_to, &self.thread_id].into_iter().flatten() {
            if !valid_ulid(id) {
                return Err(CryptoError::InvalidInput("message reference"));
            }
        }
        if self.mentions.len() > MAX_MENTIONS {
            return Err(CryptoError::InvalidInput("too many mentions"));
        }
        for m in &self.mentions {
            check_user_address(m)?;
        }
        if self.attachments.len() > MAX_ATTACHMENTS {
            return Err(CryptoError::InvalidInput("too many attachments"));
        }
        for a in &self.attachments {
            let hash_ok = !a.sha256.is_empty()
                && a.sha256.len() <= MAX_SHA256_LEN
                && a.sha256.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            if !valid_ulid(&a.id) || !hash_ok {
                return Err(CryptoError::InvalidInput("attachment"));
            }
        }
        Ok(())
    }
}

/// A decoded `signature` envelope value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaintextSignature {
    /// Random per message; a repeated nonce in a conversation is a replay.
    pub nonce: [u8; 16],
    /// Ed25519 signature over [`plaintext_signed_bytes`].
    pub signature: [u8; 64],
}

impl PlaintextSignature {
    /// The envelope value `base64url(nonce || signature)` (107 characters).
    pub fn to_base64url(&self) -> String {
        let mut out = Vec::with_capacity(PLAINTEXT_SIGNATURE_LEN);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.signature);
        b64url_encode(&out)
    }

    /// Parses the envelope value strictly (base64url without padding, exactly 80 bytes). The node
    /// uses this as its format check (`message.signature_invalid`).
    pub fn parse(value: &str) -> Result<Self> {
        let malformed = CryptoError::InvalidInput("plaintext signature");
        // 80 bytes are 107 base64url characters; checking first bounds the decoding work.
        if value.len() != 107 {
            return Err(malformed);
        }
        let bytes = b64url_decode(value).map_err(|_| malformed.clone())?;
        let (nonce, signature) = bytes.split_at_checked(16).ok_or(malformed.clone())?;
        Ok(Self {
            nonce: nonce.try_into().map_err(|_| malformed.clone())?,
            signature: signature.try_into().map_err(|_| malformed)?,
        })
    }
}

/// RFC 8785 (JCS) serialization of a content object. Fails for anything but a JSON object.
pub fn canonical_content(content: &Value) -> Result<String> {
    if !content.is_object() {
        return Err(CryptoError::InvalidInput("content must be a JSON object"));
    }
    serde_json_canonicalizer::to_string(content).map_err(|_| CryptoError::InvalidInput("content"))
}

/// RFC 8785 (JCS) serialization of arbitrary JSON text (test vectors, cross-checks).
pub fn canonical_json(json: &str) -> Result<String> {
    let value: Value = serde_json::from_str(json).map_err(|_| CryptoError::InvalidInput("JSON"))?;
    serde_json_canonicalizer::to_string(&value).map_err(|_| CryptoError::InvalidInput("JSON"))
}

/// Parses `content_jcs` and checks that it is a JSON object in canonical form. Callers that receive
/// the canonical text from another JCS implementation (the TypeScript one of the SDK) use this so that
/// both implementations are cross-checked on every signature.
pub fn parse_canonical_content(content_jcs: &str) -> Result<Value> {
    let value: Value = serde_json::from_str(content_jcs).map_err(|_| CryptoError::InvalidInput("content"))?;
    if canonical_content(&value)? != content_jcs {
        return Err(CryptoError::InvalidInput("content is not in canonical (RFC 8785) form"));
    }
    Ok(value)
}

/// The byte string the device signs (FEDERATION.md §10.3); `content_jcs` is the JCS text.
pub fn plaintext_signed_bytes(fields: &PlaintextFields, nonce: &[u8; 16], content_jcs: &[u8]) -> Result<Vec<u8>> {
    fields.validate()?;
    let mut out = Vec::with_capacity(PLAINTEXT_SIGNATURE_CONTEXT.len() + 256 + content_jcs.len());
    out.extend_from_slice(PLAINTEXT_SIGNATURE_CONTEXT);
    put_str16(&mut out, &fields.conversation);
    put_str16(&mut out, &fields.author);
    put_str16(&mut out, &fields.device_id);
    put_str16(&mut out, fields.reply_to.as_deref().unwrap_or(""));
    put_str16(&mut out, fields.thread_id.as_deref().unwrap_or(""));
    out.push(u8::from(fields.mentions_everyone));
    // Bounded by MAX_MENTIONS / MAX_ATTACHMENTS above.
    out.extend_from_slice(&u16::try_from(fields.mentions.len()).unwrap_or(u16::MAX).to_be_bytes());
    for m in &fields.mentions {
        put_str16(&mut out, m);
    }
    out.extend_from_slice(&u16::try_from(fields.attachments.len()).unwrap_or(u16::MAX).to_be_bytes());
    for a in &fields.attachments {
        put_str16(&mut out, &a.id);
        out.extend_from_slice(&a.size.to_be_bytes());
        put_str16(&mut out, &a.sha256);
    }
    out.extend_from_slice(nonce);
    put_bytes32(&mut out, content_jcs)?;
    Ok(out)
}

/// Signs a plaintext message with this device. `fields.author` and `fields.device_id` must be the
/// device's own.
pub fn sign_plaintext(device: &Device, fields: &PlaintextFields, content: &Value) -> Result<PlaintextSignature> {
    sign_plaintext_with_nonce(device, fields, content, &random_array::<16>()?)
}

/// [`sign_plaintext`] with a caller-chosen nonce (test vectors only; nonces must never repeat).
pub(crate) fn sign_plaintext_with_nonce(
    device: &Device,
    fields: &PlaintextFields,
    content: &Value,
    nonce: &[u8; 16],
) -> Result<PlaintextSignature> {
    if fields.author != device.user_address() || fields.device_id != device.device_id() {
        return Err(CryptoError::InvalidInput("author and device must be the signing device"));
    }
    let jcs = canonical_content(content)?;
    let signed = plaintext_signed_bytes(fields, nonce, jcs.as_bytes())?;
    Ok(PlaintextSignature { nonce: *nonce, signature: device.sign_raw(&signed) })
}

/// Verifies the `signature` envelope value of a plaintext message against the author device's key
/// (strict Ed25519). Returns the nonce for replay detection.
pub fn verify_plaintext(
    fields: &PlaintextFields,
    content: &Value,
    signature: &str,
    device_public_key: &[u8; 32],
) -> Result<[u8; 16]> {
    let sig = PlaintextSignature::parse(signature)?;
    let jcs = canonical_content(content)?;
    let signed = plaintext_signed_bytes(fields, &sig.nonce, jcs.as_bytes())?;
    let vk = VerifyingKey::from_bytes(device_public_key).map_err(|_| CryptoError::BadSignature)?;
    vk.verify_strict(&signed, &Signature::from_bytes(&sig.signature)).map_err(|_| CryptoError::BadSignature)?;
    Ok(sig.nonce)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use serde_json::json;

    const ALICE: &str = "alice@node.example";
    const DEV: &str = "01J9ZK3G5M8Q2W4E6R8T0Y2VA1";

    fn device() -> Device {
        Device::from_secret(ALICE, DEV, &[7u8; 32]).expect("device")
    }

    fn fields() -> PlaintextFields {
        PlaintextFields {
            conversation: "node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V00".into(),
            author: ALICE.into(),
            device_id: DEV.into(),
            reply_to: Some("01J9ZK3G5M8Q2W4E6R8T0Y2V01".into()),
            thread_id: None,
            mentions_everyone: false,
            mentions: vec!["bob@other.example".into(), "carol@node.example".into()],
            attachments: vec![PlaintextAttachment {
                id: "01J9ZK3G5M8Q2W4E6R8T0Y2V02".into(),
                size: 12345,
                sha256: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU".into(),
            }],
        }
    }

    fn content() -> Value {
        json!({ "type": "text", "body": "Hallo" })
    }

    #[test]
    fn sign_verify_roundtrip() {
        let d = device();
        let sig = sign_plaintext(&d, &fields(), &content()).expect("sign");
        let b64 = sig.to_base64url();
        assert_eq!(b64.len(), 107);
        assert_eq!(PlaintextSignature::parse(&b64).expect("parse"), sig);
        assert_eq!(verify_plaintext(&fields(), &content(), &b64, &d.public_key()).ok(), Some(sig.nonce));
        // Key order and whitespace of the content do not matter (JCS).
        let reordered: Value = serde_json::from_str(r#"{ "body" : "Hallo", "type":"text" }"#).expect("json");
        assert!(verify_plaintext(&fields(), &reordered, &b64, &d.public_key()).is_ok());
        let other = sign_plaintext(&d, &fields(), &content()).expect("sign");
        assert_ne!(other.nonce, sig.nonce, "fresh nonce per message");
    }

    #[test]
    fn every_field_is_covered() {
        let d = device();
        let pk = d.public_key();
        let sig = sign_plaintext(&d, &fields(), &content()).expect("sign").to_base64url();
        let mut variants: Vec<PlaintextFields> = Vec::new();
        let mut f = fields();
        f.conversation = "node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V09".into();
        variants.push(f);
        let mut f = fields();
        f.conversation = "evil.example/01J9ZK3G5M8Q2W4E6R8T0Y2V00".into();
        variants.push(f);
        let mut f = fields();
        f.author = "mallory@node.example".into();
        variants.push(f);
        let mut f = fields();
        f.device_id = "01J9ZK3G5M8Q2W4E6R8T0Y2VA2".into();
        variants.push(f);
        let mut f = fields();
        f.reply_to = None;
        variants.push(f);
        let mut f = fields();
        f.thread_id = Some("01J9ZK3G5M8Q2W4E6R8T0Y2V01".into());
        variants.push(f);
        let mut f = fields();
        f.mentions_everyone = true;
        variants.push(f);
        let mut f = fields();
        f.mentions.reverse();
        variants.push(f);
        let mut f = fields();
        f.mentions.pop();
        variants.push(f);
        let mut f = fields();
        f.attachments[0].size += 1;
        variants.push(f);
        let mut f = fields();
        f.attachments[0].sha256 = "x".into();
        variants.push(f);
        let mut f = fields();
        f.attachments.clear();
        variants.push(f);
        for v in variants {
            assert_eq!(verify_plaintext(&v, &content(), &sig, &pk), Err(CryptoError::BadSignature), "{v:?}");
        }
        assert_eq!(
            verify_plaintext(&fields(), &json!({ "type": "text", "body": "Hallo!" }), &sig, &pk),
            Err(CryptoError::BadSignature)
        );
        let other = Device::from_secret(ALICE, DEV, &[8u8; 32]).expect("device");
        assert_eq!(verify_plaintext(&fields(), &content(), &sig, &other.public_key()), Err(CryptoError::BadSignature));
    }

    #[test]
    fn signed_bytes_layout() {
        let nonce = [9u8; 16];
        let bytes = plaintext_signed_bytes(&fields(), &nonce, b"{}").expect("bytes");
        assert!(bytes.starts_with(PLAINTEXT_SIGNATURE_CONTEXT));
        // The end is nonce(16) || u32(2) || "{}".
        let tail = &bytes[bytes.len() - 22..];
        assert_eq!(&tail[..16], &nonce);
        assert_eq!(&tail[16..], &[0, 0, 0, 2, b'{', b'}']);
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        let d = device();
        let mut f = fields();
        f.author = "bob@node.example".into();
        assert!(sign_plaintext(&d, &f, &content()).is_err(), "only the own device signs");
        assert!(sign_plaintext(&d, &fields(), &json!([1, 2])).is_err());
        for broken in [
            |f: &mut PlaintextFields| f.conversation = "01J9ZK3G5M8Q2W4E6R8T0Y2V00".into(),
            |f: &mut PlaintextFields| f.reply_to = Some("x".into()),
            |f: &mut PlaintextFields| f.mentions.push("Bob".into()),
            |f: &mut PlaintextFields| f.attachments[0].id = "nope".into(),
            |f: &mut PlaintextFields| f.attachments[0].sha256 = "a b".into(),
            |f: &mut PlaintextFields| f.attachments[0].sha256 = "a".repeat(200),
        ] {
            let mut f = fields();
            broken(&mut f);
            assert!(plaintext_signed_bytes(&f, &[0u8; 16], b"{}").is_err(), "{f:?}");
        }
        let sig = sign_plaintext(&d, &fields(), &content()).expect("sign").to_base64url();
        for bad in ["", "abc", &sig[..106], &format!("{sig}A"), &format!("{}+", &sig[..106])] {
            assert!(PlaintextSignature::parse(bad).is_err(), "{bad}");
            assert!(verify_plaintext(&fields(), &content(), bad, &d.public_key()).is_err());
        }
    }

    #[test]
    fn canonical_checks() {
        assert_eq!(canonical_json(r#"{"b":[1.0,2e1],"a":"€"}"#).ok().as_deref(), Some(r#"{"a":"€","b":[1,20]}"#));
        assert!(canonical_json("{").is_err());
        assert!(parse_canonical_content(r#"{"a":1,"b":2}"#).is_ok());
        assert!(parse_canonical_content(r#"{"b":2,"a":1}"#).is_err());
        assert!(parse_canonical_content(r#"{"a": 1}"#).is_err());
        assert!(parse_canonical_content("[1]").is_err());
    }

    #[test]
    fn fields_parse_from_json() {
        let f: PlaintextFields = serde_json::from_value(json!({
            "conversation": "node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V00",
            "author": ALICE,
            "device_id": DEV,
            "mentions": ["bob@other.example"],
            "attachments": [{ "id": "01J9ZK3G5M8Q2W4E6R8T0Y2V02", "size": 1, "sha256": "abc" }]
        }))
        .expect("fields");
        assert_eq!(f.reply_to, None);
        assert!(!f.mentions_everyone);
        assert!(
            serde_json::from_value::<PlaintextFields>(
                json!({ "conversation": "x", "author": ALICE, "device_id": DEV, "extra": 1 })
            )
            .is_err()
        );
    }
}
