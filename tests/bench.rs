// SPDX-License-Identifier: MPL-2.0
//! Timing of the MLS client's hot paths for groups of growing size (not a test of behaviour, ignored by default):
//! `cargo test --release --test bench -- --ignored --nocapture`.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::{Duration, Instant};

use tavrn_crypto::{Client, Device};

const CONV: &str = "node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V00";
const MSG: &str = r#"{"type":"text","body":"hello"}"#;

fn client(i: usize) -> Client {
    let device = format!("01J9ZK3G5M8Q2W4E6R8T0Y2{i:03}");
    Client::new(Device::generate(&format!("user{i}@node.example"), &device).expect("device"))
}

fn time(iters: u32, mut f: impl FnMut()) -> Duration {
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    t.elapsed() / iters
}

fn bench(n: usize) {
    let mut alice = client(0);
    alice.create_group(CONV).expect("create");
    let mut others: Vec<Client> = (1..n).map(client).collect();
    let kps: Vec<Vec<u8>> = others.iter_mut().map(|c| c.create_key_package().expect("kp")).collect();
    let out = alice.add_members(CONV, &kps).expect("add");
    alice.merge_pending_commit(CONV).expect("merge");
    let welcome = out.welcome.expect("welcome");
    others[0].join_by_welcome(&welcome).expect("join");
    if n > 2 {
        others[n - 2].join_by_welcome(&welcome).expect("join");
    }
    let (bob, rest) = others.split_first_mut().expect("members");
    let bob: &Client = bob;
    // The author is the last leaf (with more than two members): the leaf check of decrypt_content walks the roster.
    let author_client: &Client = if n > 2 { rest.last().expect("last") } else { &alice };
    let content = author_client.encrypt_content(CONV, MSG).expect("encrypt");
    let d = author_client.device();
    let (author, device, key) = (d.user_address().to_owned(), d.device_id().to_owned(), d.public_key());
    let iters = 200;
    let has = time(iters, || assert!(bob.has_group(CONV)));
    let roster = time(iters, || assert_eq!(bob.roster(CONV).expect("roster").len(), n));
    let epoch = time(iters, || assert!(bob.current_epoch(CONV).expect("epoch") > 0));
    let decrypt = time(iters, || {
        bob.decrypt_content(CONV, &author, &device, &content, Some(&key)).expect("decrypt");
    });
    // What @tavrn/e2ee did per message before the leaf check moved into decrypt_content: hasGroup, roster, decrypt.
    let js_before = time(iters, || {
        assert!(bob.has_group(CONV));
        let identity = format!("{author}/{device}");
        let leaf = bob.roster(CONV).expect("roster").into_iter().find(|e| e.identity == identity).expect("leaf");
        assert_eq!(leaf.signature_key, key);
        bob.decrypt_content(CONV, &author, &device, &content, Some(&key)).expect("decrypt");
    });
    let encrypt = time(iters, || {
        alice.encrypt_content(CONV, MSG).expect("encrypt");
    });
    let mut state = Vec::new();
    let export = time(20, || state = alice.export_state().expect("export").to_vec());
    let import = time(20, || {
        Client::import_state(&state).expect("import");
    });
    println!(
        "members={n:4}: has_group={has:?} roster={roster:?} current_epoch={epoch:?} decrypt(key)={decrypt:?} \
         e2ee decrypt path (has_group+roster+decrypt)={js_before:?} encrypt={encrypt:?} \
         export_state={} bytes in {export:?} import_state={import:?}",
        state.len()
    );
}

#[test]
#[ignore = "timing only: cargo test --release --test bench -- --ignored --nocapture"]
fn mls_client_hot_paths() {
    for n in [2usize, 20, 100, 500] {
        bench(n);
    }
}
