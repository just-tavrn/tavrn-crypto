// SPDX-License-Identifier: MPL-2.0
//! Checks the crate against `protocol/testvectors/federation.json` (FEDERATION.md §10: safety
//! numbers, QR payload, JCS and plaintext signatures). The TypeScript side (SDK `jcs`, web client)
//! runs against the same file.
#![allow(clippy::expect_used)]

use serde_json::{Value, json};

use crate::device::Device;
use crate::keys::MasterSecret;
use crate::plaintext::{
    PlaintextAttachment, PlaintextFields, canonical_content, canonical_json, plaintext_signed_bytes,
    sign_plaintext_with_nonce, verify_plaintext,
};
use crate::util::{b64url_decode_array, b64url_encode};
use crate::verify::{group_safety_number, parse_verify_payload, safety_number, verify_payload, verify_payload_matches};

const VECTORS: &str = include_str!("../protocol/testvectors/federation.json");

fn seq<const N: usize>(start: u8) -> [u8; N] {
    std::array::from_fn(|i| start.wrapping_add(i as u8))
}

/// JSON texts and their RFC 8785 form (incl. the examples of RFC 8785 §3.2.2 and §3.2.3). `%u` stands
/// for the JSON escape backslash-u (expanded by [`json_text`]) so that editors keep the escapes as is.
const JCS_INPUTS: &[&str] = &[
    r#"{"type":"text","body":"Hallo"}"#,
    r#"{ "b" : 2, "a" : 1, "c": { "z": [3, 2, 1], "y": null } }"#,
    r#"{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"%u20ac$%u000F%u000aA'%u0042%u0022%u005c\\\"\/","literals":[null,true,false]}"#,
    r#"{"%u20ac":"Euro Sign","\r":"Carriage Return","%ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","%ud83d%ude00":"Emoji: Grinning Face","%u0080":"Control","%u00f6":"Latin Small Letter O With Diaeresis"}"#,
    r#"{"literal":"€ö😀","escaped":"%u00e9"}"#,
    r#"[0, -0, 1.0, -1.5, 1e21, 1e-7, 123456789, 9007199254740993, 0.1, 1e+2]"#,
    r#"{"s":"line\nbreak\ttab %u0001 %u001f %u007f %u2028 </script>"}"#,
    r#"{"empty":{},"list":[],"str":""}"#,
];

fn json_text(s: &str) -> String {
    s.replace("%u", "\\u")
}

/// Computes all vectors from fixed inputs.
fn compute() -> Value {
    let alice = "alice@a.example";
    let bob = "bob@b.example";
    let ka = MasterSecret::from_bytes(seq(0)).identity_public_key();
    let kb = MasterSecret::from_bytes(seq(100)).identity_public_key();
    let number = safety_number(alice, &ka, bob, &kb).expect("safety number");
    let payload = verify_payload(alice, &ka, bob, &kb).expect("payload");
    let carol = "carol@a.example";
    let kc = MasterSecret::from_bytes(seq(200)).identity_public_key();
    let number2 = safety_number(carol, &kc, alice, &ka).expect("safety number");
    let payload2 = verify_payload(carol, &kc, alice, &ka).expect("payload");

    let invalid_payloads = [
        payload.replace("v=1", "v=2"),
        payload.replace("tavrn:verify?", "tavrn:verify?x=1&"),
        format!("{payload}&x=1"),
        verify_payload(alice, &ka, bob, &kb).expect("payload").replace(alice, "Alice@a.example"),
        format!("tavrn:verify?v=1&a={bob}&ka={}&b={alice}&kb={}", b64url_encode(&kb), b64url_encode(&ka)),
        format!("tavrn:verify?v=1&a={alice}&ka={}&b={alice}&kb={}", b64url_encode(&ka), b64url_encode(&kb)),
        format!("tavrn:verify?v=1&a={alice}&ka={}&b={bob}&kb={}", b64url_encode(&ka[..31]), b64url_encode(&kb)),
        payload.replace("tavrn:verify?", "https://a.example/verify?"),
    ];

    let jcs: Vec<Value> = JCS_INPUTS
        .iter()
        .map(|input| json_text(input))
        .map(|input| json!({ "canonical": canonical_json(&input).expect("jcs"), "input": input }))
        .collect();

    let user = "alice@node.example";
    let device_id = "01J9ZK3G5M8Q2W4E6R8T0Y2VA1";
    let device = Device::from_secret(user, device_id, &seq(32)).expect("device");
    let fields = PlaintextFields {
        conversation: "node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V00".into(),
        author: user.into(),
        device_id: device_id.into(),
        reply_to: Some("01J9ZK3G5M8Q2W4E6R8T0Y2V01".into()),
        thread_id: None,
        mentions_everyone: false,
        mentions: vec!["bob@other.example".into(), "carol@node.example".into()],
        attachments: vec![PlaintextAttachment {
            id: "01J9ZK3G5M8Q2W4E6R8T0Y2V02".into(),
            size: 12345,
            sha256: b64url_encode(&seq::<32>(150)),
        }],
    };
    let content_input = &json_text(
        r#"{ "type": "text", "gif": { "width": 480, "url": "https://media.giphy.com/media/x/giphy.gif", "height": 270.0 }, "body": "Hallo **Welt** %u20ac" }"#,
    );
    let content: Value = serde_json::from_str(content_input).expect("content");
    let content_jcs = canonical_content(&content).expect("jcs");
    let nonce: [u8; 16] = seq(96);
    let signed = plaintext_signed_bytes(&fields, &nonce, content_jcs.as_bytes()).expect("signed");
    let signature = sign_plaintext_with_nonce(&device, &fields, &content, &nonce).expect("sign");

    json!({
        "description": "Reference values for FEDERATION.md §10. Binary values are base64url without padding.",
        "safety_numbers": [
            {
                "a": alice, "ka": b64url_encode(&ka), "b": bob, "kb": b64url_encode(&kb),
                "safety_number": number, "grouped": group_safety_number(&number).expect("grouped"), "payload": payload,
            },
            {
                "a": carol, "ka": b64url_encode(&kc), "b": alice, "kb": b64url_encode(&ka),
                "safety_number": number2, "grouped": group_safety_number(&number2).expect("grouped"), "payload": payload2,
            },
        ],
        "invalid_payloads": invalid_payloads,
        "jcs": jcs,
        "plaintext_signature": {
            "device_secret_key": b64url_encode(&seq::<32>(32)),
            "device_public_key": b64url_encode(&device.public_key()),
            "fields": {
                "conversation": fields.conversation,
                "author": fields.author,
                "device_id": fields.device_id,
                "reply_to": fields.reply_to,
                "thread_id": fields.thread_id,
                "mentions_everyone": fields.mentions_everyone,
                "mentions": fields.mentions,
                "attachments": [{ "id": fields.attachments[0].id, "size": fields.attachments[0].size, "sha256": fields.attachments[0].sha256 }],
            },
            "content_input": content_input,
            "content_jcs": content_jcs,
            "nonce": b64url_encode(&nonce),
            "signed": b64url_encode(&signed),
            "signature": signature.to_base64url(),
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
fn published_vectors_verify() {
    let v: Value = serde_json::from_str(VECTORS).expect("vectors JSON");
    for case in v["safety_numbers"].as_array().expect("cases") {
        let s = |k: &str| case[k].as_str().expect("string").to_owned();
        let ka = b64url_decode_array::<32>(&s("ka"), "k").expect("ka");
        let kb = b64url_decode_array::<32>(&s("kb"), "k").expect("kb");
        // Both users get the same number, whatever the argument order.
        assert_eq!(safety_number(&s("a"), &ka, &s("b"), &kb).expect("n"), s("safety_number"));
        assert_eq!(safety_number(&s("b"), &kb, &s("a"), &ka).expect("n"), s("safety_number"));
        assert!(verify_payload_matches(&s("payload"), &s("a"), &ka, &s("b"), &kb));
        assert!(verify_payload_matches(&s("payload"), &s("b"), &kb, &s("a"), &ka));
    }
    for bad in v["invalid_payloads"].as_array().expect("list") {
        assert!(parse_verify_payload(bad.as_str().expect("string")).is_err(), "{bad}");
    }
    let p = &v["plaintext_signature"];
    let fields: PlaintextFields = serde_json::from_value(p["fields"].clone()).expect("fields");
    let content: Value = serde_json::from_str(p["content_input"].as_str().expect("content")).expect("json");
    let pk = b64url_decode_array::<32>(p["device_public_key"].as_str().expect("pk"), "k").expect("pk");
    let nonce = verify_plaintext(&fields, &content, p["signature"].as_str().expect("sig"), &pk).expect("verify");
    assert_eq!(b64url_encode(&nonce), p["nonce"].as_str().expect("nonce"));
}
