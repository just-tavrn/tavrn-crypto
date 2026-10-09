// SPDX-License-Identifier: MPL-2.0
// The protocol's reference values (protocol/testvectors/encryption.json) through the built WebAssembly package:
// what a JavaScript client computes must match the Rust core byte for byte. Run `just wasm` first.
import { createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import {
  Client,
  MasterSecret,
  RecoveryKey,
  canonicalJson,
  decryptFile,
  decryptScene,
  encryptScene,
  inboxPublicKey,
  initSync,
  passkeyMethod,
  passkeyWrappingKey,
  secretStoragePrfInput,
  unwrapIdentityKey,
  unwrapMasterSecret,
  verifyContinuity,
  verifyDeviceAttestation,
} from "../dist/tavrn_crypto.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Vectors = Record<string, any>;
const V: Vectors = JSON.parse(readFileSync(new URL("../../protocol/testvectors/encryption.json", import.meta.url), "utf8"));
const b = (s: string) => new Uint8Array(Buffer.from(s, "base64url"));
const s64 = (u: Uint8Array) => Buffer.from(u).toString("base64url");
const text = (u: Uint8Array) => new TextDecoder().decode(u);
/** A reader that holds only the content key of one epoch (as after a history import). */
function reader(conversation: string, epoch: number, key: string): Client {
  const c = Client.create("reader@node.example", "01J9ZK3G5M8Q2W4E6R8T0Y2VZZ");
  c.importEpochKey(conversation, epoch, b(key));
  return c;
}
/** `str16`: a 16-bit big-endian length and the UTF-8 bytes (ENCRYPTION.md §0). */
function str16(s: string): Buffer {
  const bytes = Buffer.from(s, "utf8");
  const len = Buffer.alloc(2);
  len.writeUInt16BE(bytes.length);
  return Buffer.concat([len, bytes]);
}

beforeAll(() => {
  initSync({ module: readFileSync(new URL("../dist/tavrn_crypto_bg.wasm", import.meta.url)) });
});

describe("encryption.json through the WebAssembly package", () => {
  const device = V.device_attestation;
  const deviceKey = b(device.device_public_key);

  it("keys, local storage key and device attestation", () => {
    const master = MasterSecret.fromKeyFile(V.keys.key_file_words);
    expect(s64(master.toBytes())).toBe(V.keys.master_secret);
    expect(s64(master.identityPublicKey())).toBe(V.keys.identity_public_key);
    expect(s64(master.backupKey())).toBe(V.keys.backup_key);
    const local = MasterSecret.fromBytes(b(V.local_storage_key.master_secret));
    expect(s64(local.localStorageKey(V.local_storage_key.device_id))).toBe(V.local_storage_key.key);
    expect(verifyDeviceAttestation(device.user_address, device.device_id, deviceKey, b(device.signature), master.identityPublicKey())).toBe(true);
    master.free();
    local.free();
  });

  it("content, also with the signed context, and history shares", () => {
    for (const [name, field] of [["content", "content"], ["content_context", "content"], ["history_share", "ciphertext"]] as const) {
      const v = V[name];
      const c = reader(v.conversation, v.epoch, v.content_key);
      const json = c.decryptContent(v.conversation, v.author, v.device_id, v[field], deviceKey);
      expect(json, name).toBe(name === "history_share" ? v.payload : v.json);
      c.free();
    }
    const ctx = JSON.parse(V.content_context.json).ctx;
    expect(ctx).toEqual({ thread_id: V.content_context.thread_id, reply_to: V.content_context.reply_to });
    expect(canonicalJson(V.history_share.payload)).toBe(V.history_share.payload);
    expect(JSON.parse(V.history_share.payload)).toMatchObject({ type: "history_keys", v: 1, to: V.history_share.to, conversation: V.history_share.conversation });
  });

  it("backups, files and whiteboard scenes", () => {
    const c = Client.create("reader@node.example", "01J9ZK3G5M8Q2W4E6R8T0Y2VZZ");
    expect(c.importBackup(V.backup.conversation, b(V.backup.backup_key), b(V.backup.blob))).toBe(2);
    expect(s64(c.exportEpochKey(V.backup.conversation, 41))).toBe(V.backup.epoch_keys["41"]);
    c.free();
    expect(s64(decryptFile(b(V.file.ciphertext), b(V.file.key), b(V.file.nonce), b(V.file.sha256)))).toBe(V.file.plaintext);
    const w = V.whiteboard_scene;
    expect(text(decryptScene(b(w.backup_key), w.scene_id, "scene", b(w.scene_blob)))).toBe(w.scene);
    expect(s64(decryptScene(b(w.backup_key), w.scene_id, "thumbnail", b(w.thumbnail_blob)))).toBe(w.thumbnail);
    expect(() => decryptScene(b(w.backup_key), w.scene_id, "thumbnail", b(w.scene_blob))).toThrow();
    expect(encryptScene(b(w.backup_key), w.scene_id, "scene", new TextEncoder().encode(w.scene))[0]).toBe(1);
  });

  it("device login proof", () => {
    const d = V.device_login;
    const message = Buffer.concat([Buffer.from("tavrn device login v1\0"), str16(d.device_id), str16(d.user_address), str16(d.nonce)]);
    expect(s64(message)).toBe(d.message);
    const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: device.device_public_key }, format: "jwk" });
    expect(verify(null, message, key, Buffer.from(b(d.proof)))).toBe(true);
    // The package signs the same message.
    const c = Client.create(d.user_address, d.device_id);
    const own = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: s64(c.devicePublicKey) }, format: "jwk" });
    expect(verify(null, message, own, Buffer.from(c.signDeviceLogin(d.nonce)))).toBe(true);
    c.free();
  });

  it("secret storage and identity rotation", () => {
    const ss = V.secret_storage;
    const recovery = RecoveryKey.fromText(ss.recovery_key_words);
    expect(s64(recovery.wrappingKey())).toBe(ss.recovery_wrapping_key);
    expect(s64(unwrapMasterSecret(b(ss.recovery_wrapped), recovery.wrappingKey(), ss.user_address, "recovery").toBytes())).toBe(ss.master_secret);
    expect(s64(secretStoragePrfInput())).toBe(ss.prf_input);
    expect(passkeyMethod("Y3JlZGVudGlhbC0x")).toBe(ss.passkey_method);
    expect(s64(passkeyWrappingKey(b(ss.prf_output)))).toBe(ss.passkey_wrapping_key);
    recovery.free();
    const r = V.identity_rotation;
    const master = MasterSecret.fromBytes(b(r.master_secret));
    expect(s64(unwrapIdentityKey(master, b(r.identity_blob), r.user_address).publicKey())).toBe(r.rotated_public_key);
    expect(verifyContinuity(JSON.stringify(r.continuity))).toBe(true);
    master.free();
  });

  it("webhook inbox and sealed unlock material", () => {
    const w = V.webhook_inbox;
    expect(s64(inboxPublicKey(b(w.content_key)))).toBe(w.inbox_public_key);
    const c = reader(w.conversation, w.epoch, w.content_key);
    expect(c.openSealed(w.conversation, w.epoch, b(w.sealed))).toBe(w.payload);
    c.free();
    // The app's key pair is the inbox pair of its seed (FEDERATION.md §8 step 3).
    const u = V.sealed_unlock;
    expect(s64(inboxPublicKey(b(u.app_seed)))).toBe(u.app_public_key);
    const opener = reader("app.invalid/00000000000000000000000000", 0, u.app_seed);
    expect(opener.openSealed("app.invalid/00000000000000000000000000", 0, b(u.sealed))).toBe(u.payload);
    expect(JSON.parse(u.payload)).toMatchObject({ type: "tavrn.connect.unlock.v1", prf_output: V.secret_storage.prf_output });
    opener.free();
  });
});
