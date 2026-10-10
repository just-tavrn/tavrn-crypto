// SPDX-License-Identifier: MPL-2.0
// End-to-end test of the built WebAssembly package: several devices, the node simulated in
// between. Run `just wasm` (or `./build-wasm.sh`) first.
import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import {
  Client,
  MasterSecret,
  RecoveryKey,
  canonicalJson,
  capability,
  contentEpoch,
  decryptContentWithKey,
  decryptFile,
  decryptScene,
  encryptFile,
  encryptScene,
  initSync,
  passkeyMethod,
  parseVerifyPayload,
  passkeyWrappingKey,
  safetyNumber,
  sealShareKey,
  secretStoragePrfInput,
  unwrapMasterSecret,
  verifyDeviceAttestation,
  verifyDeviceShareKey,
  verifyPayload,
  verifyPayloadMatches,
  verifyPlaintext,
  wrapMasterSecret,
} from "../dist/tavrn_crypto.js";

const CONV = "node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V00";
const ALICE = "alice@node.example";
const BOB = "bob@other.example";
const CAROL = "carol@node.example";
const DEV_A = "01J9ZK3G5M8Q2W4E6R8T0Y2VA1";
const DEV_B = "01J9ZK3G5M8Q2W4E6R8T0Y2VB1";
const DEV_C = "01J9ZK3G5M8Q2W4E6R8T0Y2VC1";
const DEV_A2 = "01J9ZK3G5M8Q2W4E6R8T0Y2VA2";
const MSG = JSON.stringify({ type: "text", body: "hello from wasm" });

beforeAll(() => {
  initSync({ module: readFileSync(new URL("../dist/tavrn_crypto_bg.wasm", import.meta.url)) });
});

function errorName(f: () => unknown): string {
  try {
    f();
  } catch (e) {
    return (e as Error).name;
  }
  return "no error";
}

describe("@tavrn/crypto (wasm)", () => {
  it("reports its capability", () => {
    expect(capability()).toBe("e2ee.mls1");
  });

  it("round-trips the key file and attests devices", () => {
    const master = MasterSecret.generate();
    const file = master.toKeyFile(ALICE);
    expect(file).toContain("key: ");
    const restored = MasterSecret.fromKeyFile(file);
    expect(restored.identityPublicKey()).toEqual(master.identityPublicKey());
    expect(restored.backupKey()).toEqual(master.backupKey());
    const words = file.split("\n").find((l) => l.startsWith("words: "))!.slice(7);
    expect(MasterSecret.fromKeyFile(words).toBytes()).toEqual(master.toBytes());
    expect(errorName(() => MasterSecret.fromKeyFile("key: AAAA"))).toBe("key_file_malformed");

    const device = Client.create(ALICE, DEV_A);
    const sig = master.attestDevice(ALICE, DEV_A, device.devicePublicKey);
    const id = master.identityPublicKey();
    expect(verifyDeviceAttestation(ALICE, DEV_A, device.devicePublicKey, sig, id)).toBe(true);
    expect(verifyDeviceAttestation(BOB, DEV_A, device.devicePublicKey, sig, id)).toBe(false);
    expect(verifyDeviceAttestation(ALICE, DEV_A, device.devicePublicKey, sig, MasterSecret.generate().identityPublicKey())).toBe(false);
    expect(verifyDeviceAttestation(ALICE, DEV_A, device.devicePublicKey, new Uint8Array(3), id)).toBe(false);
  });

  it("runs the group lifecycle: create, add, message, external join, rotation, history", () => {
    // Alice creates the conversation; the node stores the GroupInfo.
    let alice = Client.create(ALICE, DEV_A);
    const bob = Client.create(BOB, DEV_B);
    let groupInfo = alice.createGroup(CONV);
    expect(alice.currentEpoch(CONV)).toBe(0);

    // Alice adds Bob with a KeyPackage fetched from Bob's home node.
    const add = alice.addMembers(CONV, [bob.createKeyPackage()]);
    expect(add.epoch).toBe(0);
    expect(alice.mergePendingCommit(CONV)).toBe(1);
    groupInfo = add.groupInfo;
    const joined = bob.joinByWelcome(add.welcome!);
    expect(joined.conversation).toBe(CONV);
    expect(joined.epoch).toBe(1);

    // Two parties exchange messages.
    const c1 = alice.encryptContent(CONV, MSG);
    expect(contentEpoch(c1)).toBe(1);
    expect(bob.decryptContent(CONV, ALICE, DEV_A, c1)).toBe(MSG);
    const c2 = bob.encryptContent(CONV, MSG);
    expect(alice.decryptContent(CONV, BOB, DEV_B, c2)).toBe(MSG);
    expect(errorName(() => bob.decryptContent(CONV, BOB, DEV_B, c1))).toBe("decryption_failed");

    // State survives a reload (IndexedDB round trip).
    alice = Client.importState(alice.exportState());
    expect(alice.decryptContent(CONV, BOB, DEV_B, c2)).toBe(MSG);

    // Carol joins by external commit.
    const carol = Client.create(CAROL, DEV_C);
    const join = carol.joinByExternalCommit(CONV, groupInfo);
    expect(join.welcome).toBeUndefined();
    expect(carol.mergePendingCommit(CONV)).toBe(2);
    for (const member of [alice, bob]) {
      const outcome = member.processHandshake(CONV, join.commit);
      expect(outcome.epoch).toBe(2);
      expect(outcome.externalJoin).toBe(true);
      expect(outcome.committer).toBe(`${CAROL}/${DEV_C}`);
    }
    expect(errorName(() => alice.processHandshake(CONV, join.commit))).toBe("stale_epoch");
    expect(alice.roster(CONV).map((e) => e.identity)).toEqual([
      `${ALICE}/${DEV_A}`,
      `${BOB}/${DEV_B}`,
      `${CAROL}/${DEV_C}`,
    ]);
    const c3 = carol.encryptContent(CONV, MSG);
    expect(alice.decryptContent(CONV, CAROL, DEV_C, c3)).toBe(MSG);
    expect(bob.decryptContent(CONV, CAROL, DEV_C, c3)).toBe(MSG);

    // Epoch key rotation.
    const k2 = alice.exportEpochKey(CONV, 2);
    const up = bob.selfUpdate(CONV);
    expect(bob.mergePendingCommit(CONV)).toBe(3);
    alice.processHandshake(CONV, up.commit);
    carol.processHandshake(CONV, up.commit);
    expect(alice.exportEpochKey(CONV, 3)).not.toEqual(k2);

    // Voice frame keys (ENCRYPTION.md §5a): same for all members, current epoch only, not the content key.
    const v3 = alice.exportVoiceKey(CONV, 3);
    expect(v3).toHaveLength(32);
    expect(carol.exportVoiceKey(CONV, 3)).toEqual(v3);
    expect(v3).not.toEqual(alice.exportEpochKey(CONV, 3));
    expect(errorName(() => alice.exportVoiceKey(CONV, 2))).toBe("unknown_epoch");
    const c4 = alice.encryptContent(CONV, MSG);
    expect(contentEpoch(c4)).toBe(3);
    expect(carol.decryptContent(CONV, ALICE, DEV_A, c4)).toBe(MSG);
    expect(bob.decryptContent(CONV, ALICE, DEV_A, c1)).toBe(MSG);

    // History backup restores old epochs on Alice's new device.
    const master = MasterSecret.generate();
    const backup = alice.exportBackup(CONV, master.backupKey());
    const laptop = Client.create(ALICE, DEV_A2);
    expect(laptop.importBackup(CONV, master.backupKey(), backup)).toBe(4);
    expect(Array.from(laptop.knownEpochs(CONV))).toEqual([0, 1, 2, 3]);
    expect(laptop.decryptContent(CONV, BOB, DEV_B, c2, bob.devicePublicKey)).toBe(MSG);
    expect(errorName(() => laptop.decryptContent(CONV, BOB, DEV_B, c2))).toBe("unknown_sender");
    expect(errorName(() => laptop.importBackup(CONV, MasterSecret.generate().backupKey(), backup))).toBe(
      "decryption_failed",
    );

    // Removal: Bob loses access to new epochs.
    const rm = alice.removeMembers(CONV, [`${BOB}/${DEV_B}`]);
    alice.mergePendingCommit(CONV);
    expect(bob.processHandshake(CONV, rm.commit).selfRemoved).toBe(true);
    carol.processHandshake(CONV, rm.commit);
    const c5 = alice.encryptContent(CONV, MSG);
    expect(carol.decryptContent(CONV, ALICE, DEV_A, c5)).toBe(MSG);
    expect(errorName(() => bob.decryptContent(CONV, ALICE, DEV_A, c5))).toBe("unknown_epoch");
  });

  it("removes exactly the leaf with the given key when two leaves name one device", () => {
    const alice = Client.create(ALICE, DEV_A);
    const bob = Client.create(BOB, DEV_B);
    const forged = Client.create(BOB, DEV_B);
    alice.createGroup(CONV);
    alice.addMembers(CONV, [bob.createKeyPackage(), forged.createKeyPackage()]);
    alice.mergePendingCommit(CONV);
    expect(errorName(() => alice.removeLeaves(CONV, [`${BOB}/${DEV_B}`], []))).toBe("invalid_input");
    alice.removeLeaves(CONV, [`${BOB}/${DEV_B}`], [forged.devicePublicKey]);
    alice.mergePendingCommit(CONV);
    expect(alice.roster(CONV).map((e) => Buffer.from(e.signatureKey).toString("hex"))).toEqual([
      Buffer.from(alice.devicePublicKey).toString("hex"),
      Buffer.from(bob.devicePublicKey).toString("hex"),
    ]);
  });

  it("publishes a share key per device and seals history shares v2 to it", () => {
    const alice = Client.create(ALICE, DEV_A);
    const bob = Client.create(BOB, DEV_B);
    const carol = Client.create(CAROL, DEV_C);
    alice.createGroup(CONV);
    const sk = bob.shareKey();
    expect(sk.publicKey).toHaveLength(32);
    expect(sk.signature).toHaveLength(64);
    expect(verifyDeviceShareKey(DEV_B, bob.devicePublicKey, sk.publicKey, sk.signature)).toBe(true);
    expect(verifyDeviceShareKey(DEV_B, carol.devicePublicKey, sk.publicKey, sk.signature)).toBe(false);
    expect(Buffer.from(Client.create(BOB, DEV_B).shareKey().publicKey)).not.toEqual(Buffer.from(sk.publicKey));
    const payload = JSON.stringify({ type: "history_keys", v: 2 });
    const share = alice.encryptShare(CONV, payload, [sk.publicKey, carol.shareKey().publicKey]);
    expect(share.epoch).toBe(0);
    expect(contentEpoch(share.content)).toBe(0);
    expect(share.boxes).toHaveLength(2);
    expect(share.boxes[0]).toHaveLength(80);
    const box = share.boxes[0]!;
    const key = bob.openShareBox(box);
    expect(key).toHaveLength(32);
    expect(decryptContentWithKey(key, CONV, ALICE, DEV_A, share.content, alice.devicePublicKey)).toBe(payload);
    expect(decryptContentWithKey(carol.openShareBox(share.boxes[1]!), CONV, ALICE, DEV_A, share.content, alice.devicePublicKey)).toBe(payload);
    expect(sealShareKey(sk.publicKey, key)).toHaveLength(80);
    expect(errorName(() => alice.encryptShare(CONV, payload, []))).toBe("invalid_input");
    expect(errorName(() => carol.openShareBox(box))).toBe("decryption_failed");
    expect(errorName(() => Client.create(BOB, DEV_B).openShareBox(box))).toBe("decryption_failed");
    expect(errorName(() => decryptContentWithKey(new Uint8Array(32), CONV, ALICE, DEV_A, share.content, alice.devicePublicKey))).toBe("decryption_failed");
    for (const c of [alice, bob, carol]) c.free();
  });

  it("encrypts attachments", () => {
    const data = new TextEncoder().encode("attachment bytes");
    const f = encryptFile(data);
    expect(f.key.length).toBe(32);
    expect(f.nonce.length).toBe(12);
    expect(decryptFile(f.ciphertext, f.key, f.nonce, f.sha256)).toEqual(data);
    const tampered = f.ciphertext.slice();
    tampered[0] ^= 1;
    expect(errorName(() => decryptFile(tampered, f.key, f.nonce, f.sha256))).toBe("decryption_failed");
    expect(errorName(() => decryptFile(f.ciphertext, f.key.slice(1), f.nonce, f.sha256))).toBe("invalid_input");
  });

  it("rejects malformed input with errors instead of crashing", () => {
    const c = Client.create(ALICE, DEV_A);
    expect(errorName(() => Client.create("bad", DEV_A))).toBe("invalid_input");
    expect(errorName(() => Client.importState(new Uint8Array([1, 2, 3])))).toBe("state_malformed");
    expect(errorName(() => c.joinByWelcome(new Uint8Array(100)))).toBe("invalid_input");
    expect(errorName(() => c.joinByExternalCommit(CONV, new Uint8Array(0)))).toBe("invalid_input");
    expect(errorName(() => c.encryptContent(CONV, MSG))).toBe("unknown_group");
    expect(errorName(() => c.exportEpochKey(CONV, -1))).toBe("invalid_input");
    expect(errorName(() => c.exportEpochKey(CONV, 1.5))).toBe("invalid_input");
    expect(errorName(() => contentEpoch("***"))).toBe("invalid_input");
    // The client stays usable afterwards.
    c.createGroup(CONV);
    expect(c.currentEpoch(CONV)).toBe(0);
  });

  it("wraps the master secret for the secret storage (recovery key and passkey PRF)", () => {
    const master = MasterSecret.generate();
    const recovery = RecoveryKey.generate();
    const words = recovery.toWords();
    expect(words.split(" ")).toHaveLength(24);
    expect(recovery.toText(ALICE)).toContain(`key: ${recovery.toCompact()}`);

    // Registration: wrap with the recovery key, upload as method "recovery".
    const entry = wrapMasterSecret(master, recovery.wrappingKey(), ALICE, "recovery");
    expect(entry).toHaveLength(61);

    // New device: the user types the words, the entry is unwrapped locally.
    const typed = RecoveryKey.fromText(words.toUpperCase());
    expect(typed.toCompact()).toBe(recovery.toCompact());
    expect(unwrapMasterSecret(entry, typed.wrappingKey(), ALICE, "recovery").toBytes()).toEqual(master.toBytes());
    expect(errorName(() => unwrapMasterSecret(entry, RecoveryKey.generate().wrappingKey(), ALICE, "recovery"))).toBe(
      "decryption_failed",
    );
    expect(errorName(() => unwrapMasterSecret(entry, typed.wrappingKey(), BOB, "recovery"))).toBe("decryption_failed");
    expect(errorName(() => RecoveryKey.fromText(master.toKeyFile(ALICE)))).toBe("key_file_wrong_kind");
    expect(errorName(() => RecoveryKey.fromText("not a key"))).toBe("key_file_malformed");

    // Passkey: the PRF output of the credential derives the wrapping key.
    expect(new TextDecoder().decode(secretStoragePrfInput())).toBe("tavrn secret storage prf v1");
    const method = passkeyMethod("Y3JlZGVudGlhbC0x");
    expect(method).toBe("passkey:Y3JlZGVudGlhbC0x");
    const prf = new Uint8Array(32).fill(7);
    const passkeyEntry = wrapMasterSecret(master, passkeyWrappingKey(prf), ALICE, method);
    expect(unwrapMasterSecret(passkeyEntry, passkeyWrappingKey(prf), ALICE, method).toBytes()).toEqual(master.toBytes());
    expect(errorName(() => unwrapMasterSecret(passkeyEntry, passkeyWrappingKey(prf), ALICE, "recovery"))).toBe(
      "decryption_failed",
    );
    expect(errorName(() => passkeyWrappingKey(new Uint8Array(31)))).toBe("invalid_input");
    expect(errorName(() => passkeyMethod("a/b"))).toBe("invalid_input");
    expect(errorName(() => wrapMasterSecret(master, new Uint8Array(3), ALICE, "recovery"))).toBe("invalid_input");
  });

  it("derives a device-specific local storage key", () => {
    const master = MasterSecret.fromBytes(new Uint8Array(32).fill(42));
    const a = master.localStorageKey(DEV_A);
    expect(a).toHaveLength(32);
    expect(MasterSecret.fromBytes(new Uint8Array(32).fill(42)).localStorageKey(DEV_A)).toEqual(a);
    expect(master.localStorageKey(DEV_A2)).not.toEqual(a);
    expect(master.backupKey()).not.toEqual(a);
    expect(errorName(() => master.localStorageKey("not-a-device"))).toBe("invalid_input");
  });
});

describe("identity verification and plaintext signatures (FEDERATION.md §10)", () => {
  const vectors = JSON.parse(readFileSync(new URL("../../protocol/testvectors/federation.json", import.meta.url), "utf8"));
  const b64 = (s: string) => new Uint8Array(Buffer.from(s, "base64url"));
  const msgJcs = JSON.stringify({ body: "hello from wasm", type: "text" });

  it("computes the published safety numbers and payloads in either order", () => {
    for (const v of vectors.safety_numbers) {
      expect(safetyNumber(v.a, b64(v.ka), v.b, b64(v.kb))).toBe(v.safety_number);
      expect(safetyNumber(v.b, b64(v.kb), v.a, b64(v.ka))).toBe(v.safety_number);
      expect(verifyPayload(v.b, b64(v.kb), v.a, b64(v.ka))).toBe(v.payload);
      const parsed = parseVerifyPayload(v.payload);
      expect([parsed.a, parsed.b].sort()).toEqual([v.a, v.b].sort());
      expect(verifyPayloadMatches(v.payload, v.a, b64(v.ka), v.b, b64(v.kb))).toBe(true);
      expect(verifyPayloadMatches(v.payload, v.a, b64(v.kb), v.b, b64(v.ka))).toBe(false);
    }
    for (const bad of vectors.invalid_payloads) expect(errorName(() => parseVerifyPayload(bad))).toBe("invalid_input");
    expect(errorName(() => safetyNumber(ALICE, new Uint8Array(32), ALICE, new Uint8Array(32)))).toBe("invalid_input");
  });

  it("canonicalizes JSON like the published JCS vectors", () => {
    for (const v of vectors.jcs) expect(canonicalJson(v.input)).toBe(v.canonical);
  });

  it("verifies the published plaintext signature and signs new ones", () => {
    const p = vectors.plaintext_signature;
    const fields = JSON.stringify(p.fields);
    const pk = b64(p.device_public_key);
    expect(verifyPlaintext(fields, p.content_jcs, p.signature, pk)).toBe(true);
    expect(verifyPlaintext(JSON.stringify({ ...p.fields, mentions_everyone: true }), p.content_jcs, p.signature, pk)).toBe(false);
    // Content that is not in canonical form is refused (cross-check of the JCS implementations).
    expect(errorName(() => verifyPlaintext(fields, p.content_input, p.signature, pk))).toBe("invalid_input");
    expect(errorName(() => verifyPlaintext(fields, p.content_jcs, "short", pk))).toBe("invalid_input");

    const client = Client.create(ALICE, DEV_A);
    const own = JSON.stringify({ conversation: CONV, author: ALICE, device_id: DEV_A, mentions: [BOB], attachments: [] });
    const signature = client.signPlaintext(own, msgJcs);
    expect(signature).toHaveLength(107);
    expect(verifyPlaintext(own, msgJcs, signature, client.devicePublicKey)).toBe(true);
    const other = Client.create(ALICE, DEV_A);
    expect(verifyPlaintext(own, msgJcs, signature, other.devicePublicKey)).toBe(false);
    // Only the own device signs.
    expect(errorName(() => client.signPlaintext(JSON.stringify({ conversation: CONV, author: BOB, device_id: DEV_A }), msgJcs))).toBe("invalid_input");
    client.free();
    other.free();
  });

  it("encrypts whiteboard scenes under the backup key, bound to the scene id and the part", () => {
    const master = MasterSecret.generate();
    const key = master.backupKey();
    const id = "01J9ZK3G5M8Q2W4E6R8T0Y2VS1";
    const json = new TextEncoder().encode(JSON.stringify({ elements: [{ id: "a", type: "rectangle" }] }));
    const blob = encryptScene(key, id, "scene", json);
    expect(blob[0]).toBe(1);
    expect(new TextDecoder().decode(decryptScene(key, id, "scene", blob))).toContain("rectangle");
    expect(errorName(() => decryptScene(key, id, "thumbnail", blob))).toBe("decryption_failed");
    expect(errorName(() => decryptScene(key, "01J9ZK3G5M8Q2W4E6R8T0Y2VS2", "scene", blob))).toBe("decryption_failed");
    expect(errorName(() => decryptScene(MasterSecret.generate().backupKey(), id, "scene", blob))).toBe("decryption_failed");
    expect(errorName(() => encryptScene(key, "../x", "scene", json))).toBe("invalid_input");
    expect(errorName(() => encryptScene(key, id, "other", json))).toBe("invalid_input");
    master.free();
  });
});
