/* tslint:disable */
/* eslint-disable */

/**
 * The MLS client of this device. Persist `exportState()` after every mutating call.
 */
export class Client {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    addMembers(conversation: string, key_packages: Uint8Array[]): CommitOutput;
    /**
     * Creates the group at epoch 0; returns its GroupInfo.
     */
    createGroup(conversation: string): Uint8Array;
    createKeyPackage(): Uint8Array;
    /**
     * A new device: generates its Ed25519 key.
     */
    static create(user_address: string, device_id: string): Client;
    currentEpoch(conversation: string): number;
    /**
     * Decrypts and verifies `content`. Pass `devicePublicKey` (from the verified attestation)
     * when the author device is no longer in the roster.
     */
    decryptContent(conversation: string, author: string, device_id: string, content: string, device_public_key?: Uint8Array | null): string;
    deleteGroup(conversation: string): void;
    discardPendingCommit(conversation: string): void;
    /**
     * Encrypts a JSON content object; returns the base64url `content` value.
     */
    encryptContent(conversation: string, json: string): string;
    /**
     * A history share v2 (ENCRYPTION.md §7b): `json` encrypted and signed like content of the current epoch under a
     * fresh key.
     */
    encryptShare(conversation: string, json: string): EncryptedShare;
    /**
     * Encrypted history backup of one conversation (upload to the home node).
     */
    exportBackup(conversation: string, backup_key: Uint8Array): Uint8Array;
    exportEpochKey(conversation: string, epoch: number): Uint8Array;
    /**
     * Serializes the whole client state (secret!).
     */
    exportState(): Uint8Array;
    /**
     * Voice frame key of the current epoch (32 bytes, ENCRYPTION.md §5a) for LiveKit's key provider at
     * key index `epoch % 256`. Fails unless `epoch` is the group's current epoch.
     */
    exportVoiceKey(conversation: string, epoch: number): Uint8Array;
    hasGroup(conversation: string): boolean;
    /**
     * Imports a history backup; returns the number of epoch keys in it.
     */
    importBackup(conversation: string, backup_key: Uint8Array, blob: Uint8Array): number;
    importEpochKey(conversation: string, epoch: number, key: Uint8Array): void;
    /**
     * Restores a client from `exportState()` bytes.
     */
    static importState(state: Uint8Array): Client;
    /**
     * The inbox public key of `epoch` with this device's signature (needs the epoch's content key).
     */
    inboxKey(conversation: string, epoch: number): InboxKey;
    joinByExternalCommit(conversation: string, group_info: Uint8Array): CommitOutput;
    joinByWelcome(welcome: Uint8Array): WelcomeJoin;
    knownEpochs(conversation: string): Float64Array;
    mergePendingCommit(conversation: string): number;
    /**
     * Opens a sealed webhook message of `epoch`; returns the inner JSON (`unknown_epoch` without the key).
     */
    openSealed(conversation: string, epoch: number, sealed: Uint8Array): string;
    /**
     * Opens a sealed share key addressed to this device; returns the 32-byte key (`decryption_failed` otherwise).
     */
    openShareBox(sealed: Uint8Array): Uint8Array;
    processHandshake(conversation: string, message: Uint8Array): HandshakeOutcome;
    removeMembers(conversation: string, identities: string[]): CommitOutput;
    roster(conversation: string): RosterEntry[];
    selfUpdate(conversation: string): CommitOutput;
    /**
     * This device's share key and the device signature over it (ENCRYPTION.md §3.1).
     */
    shareKey(): ShareKey;
    /**
     * Device login proof over the node's login nonce (ENCRYPTION.md §3.4), 64 bytes.
     */
    signDeviceLogin(nonce: string): Uint8Array;
    /**
     * Signs a plaintext message with this device (FEDERATION.md §10.3); returns the envelope value
     * `signature`. `fieldsJson` as for `verifyPlaintext` (author and device must be this device's).
     */
    signPlaintext(fields_json: string, content_jcs: string): string;
    readonly deviceId: string;
    /**
     * Ed25519 device public key (32 bytes) = MLS leaf signature key.
     */
    readonly devicePublicKey: Uint8Array;
    /**
     * `<user>@<domain>/<device_id>`.
     */
    readonly identity: string;
    readonly userAddress: string;
}

/**
 * Messages produced by a commit; see [`mls::CommitOutput`].
 */
export class CommitOutput {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    commit: Uint8Array;
    epoch: number;
    groupInfo: Uint8Array;
    get welcome(): Uint8Array | undefined;
    set welcome(value: Uint8Array | null | undefined);
}

/**
 * An encrypted attachment: upload `ciphertext`, put `key`, `nonce`, `sha256` into the content.
 */
export class EncryptedFile {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    ciphertext: Uint8Array;
    key: Uint8Array;
    nonce: Uint8Array;
    sha256: Uint8Array;
}

/**
 * A history share v2: the content and its fresh key (seal the key to each recipient device, then zero it).
 */
export class EncryptedShare {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    content: string;
    epoch: number;
    key: Uint8Array;
}

/**
 * Result of processing a commit; see [`mls::HandshakeOutcome`].
 */
export class HandshakeOutcome {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    added: string[];
    committer: string;
    discardedPendingCommit: boolean;
    epoch: number;
    externalJoin: boolean;
    removed: string[];
    selfRemoved: boolean;
}

/**
 * An identity signing key of any generation (derived from the master secret, or rotated).
 */
export class IdentityKey {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Signs a device public key with this identity key; returns the 64-byte signature.
     */
    attestDevice(user_address: string, device_id: string, device_public_key: Uint8Array): Uint8Array;
    /**
     * From the 32-byte seed (local secure storage only).
     */
    static fromBytes(bytes: Uint8Array): IdentityKey;
    /**
     * Generation 0: the key derived from the master secret.
     */
    static fromMaster(master: MasterSecret): IdentityKey;
    /**
     * A fresh random identity key (rotation).
     */
    static generate(): IdentityKey;
    /**
     * Ed25519 public identity key (32 bytes).
     */
    publicKey(): Uint8Array;
    /**
     * The 32-byte seed (local secure storage only).
     */
    toBytes(): Uint8Array;
}

/**
 * A published inbox key: `PUT /conversations/{id}/inbox-key` (ENCRYPTION.md §5b).
 */
export class InboxKey {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    publicKey: Uint8Array;
    signature: Uint8Array;
}

/**
 * The account master secret.
 */
export class MasterSecret {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Signs a device public key with the identity key; returns the 64-byte signature.
     */
    attestDevice(user_address: string, device_id: string, device_public_key: Uint8Array): Uint8Array;
    /**
     * AES-256 backup key (32 bytes) for history backups.
     */
    backupKey(): Uint8Array;
    /**
     * Restores from the 32 raw bytes (local secure storage only).
     */
    static fromBytes(bytes: Uint8Array): MasterSecret;
    /**
     * Parses a key file, its `key:` value or its 24-word list.
     */
    static fromKeyFile(text: string): MasterSecret;
    /**
     * A new random master secret (registration, identity reset).
     */
    static generate(): MasterSecret;
    /**
     * Ed25519 public identity key (32 bytes), published by the home node.
     */
    identityPublicKey(): Uint8Array;
    /**
     * AES-256 key (32 bytes) for the client's local crypto storage of device `deviceId`.
     */
    localStorageKey(device_id: string): Uint8Array;
    /**
     * The 32 raw bytes (local secure storage only).
     */
    toBytes(): Uint8Array;
    /**
     * Text of the key file `tavrn-key-<username>.txt` for `account` (`user@domain`).
     */
    toKeyFile(account: string): string;
}

/**
 * The recovery key that unlocks the secret storage entry `recovery` (ENCRYPTION.md §2.4).
 */
export class RecoveryKey {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Parses the 24 words, the compact string or a downloaded recovery key file.
     */
    static fromText(text: string): RecoveryKey;
    /**
     * A new random recovery key (registration or regeneration).
     */
    static generate(): RecoveryKey;
    /**
     * The compact string (base64url with version byte and checksum).
     */
    toCompact(): string;
    /**
     * Text of the optional download `tavrn-recovery-<username>.txt` for `account` (`user@domain`).
     */
    toText(account: string): string;
    /**
     * The 24 words shown to the user.
     */
    toWords(): string;
    /**
     * AES-256 wrapping key (32 bytes) of the `recovery` method.
     */
    wrappingKey(): Uint8Array;
}

/**
 * A member leaf of a group.
 */
export class RosterEntry {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    identity: string;
    signatureKey: Uint8Array;
}

/**
 * A device's share key with the device signature over it (`PUT /users/me/devices/{id}/share-key`).
 */
export class ShareKey {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    publicKey: Uint8Array;
    signature: Uint8Array;
}

/**
 * A parsed QR payload; keys are base64url.
 */
export class VerifyPayload {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    a: string;
    b: string;
    ka: string;
    kb: string;
}

/**
 * Result of joining by Welcome.
 */
export class WelcomeJoin {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    conversation: string;
    epoch: number;
}

/**
 * RFC 8785 (JCS) form of a JSON text.
 */
export function canonicalJson(json: string): string;

/**
 * Capability string of this scheme (`e2ee.mls1`).
 */
export function capability(): string;

/**
 * Epoch from the plaintext header of an encrypted `content` value.
 */
export function contentEpoch(content_b64: string): number;

/**
 * Is `to` reachable from `from` through valid consecutive statements of `chain` (JSON array, oldest first)?
 */
export function continuityReaches(chain_json: string, from: string, to: string): boolean;

/**
 * Decrypts content format 1 under an explicit key (a history share v2 under the key from its box) and verifies the
 * device signature; nothing is stored.
 */
export function decryptContentWithKey(key: Uint8Array, conversation: string, author: string, device_id: string, content: string, device_public_key: Uint8Array): string;

/**
 * Checks the ciphertext hash and decrypts an attachment.
 */
export function decryptFile(ciphertext: Uint8Array, key: Uint8Array, nonce: Uint8Array, sha256: Uint8Array): Uint8Array;

/**
 * Decrypts one part of a whiteboard scene.
 */
export function decryptScene(backup_key: Uint8Array, scene_id: string, part: string, blob: Uint8Array): Uint8Array;

/**
 * The share secret key a device derives from its device secret (ENCRYPTION.md §3.1; test vectors and tools, clients
 * use `Client.shareKey` and `Client.openShareBox`).
 */
export function deviceShareSecretKey(device_secret_key: Uint8Array): Uint8Array;

/**
 * Encrypts a file with a fresh random key (AES-256-GCM, one shot).
 */
export function encryptFile(plaintext: Uint8Array): EncryptedFile;

/**
 * Encrypts one part (`"scene"` or `"thumbnail"`) of a whiteboard scene under the backup key
 * (`protocol/WHITEBOARD.md` §5).
 */
export function encryptScene(backup_key: Uint8Array, scene_id: string, part: string, plaintext: Uint8Array): Uint8Array;

/**
 * Inbox public key of write-only webhooks for the epoch whose content key is `content_key` (ENCRYPTION.md §5b;
 * test vectors and tools, clients use `Client.inboxKey`).
 */
export function inboxPublicKey(content_key: Uint8Array): Uint8Array;

/**
 * Opens a sealed share key with a raw share secret key (test vectors and tools; clients use `Client.openShareBox`).
 */
export function openShareBox(share_secret_key: Uint8Array, sealed: Uint8Array): Uint8Array;

/**
 * Parses a QR payload strictly (throws `invalid_input` for anything malformed).
 */
export function parseVerifyPayload(text: string): VerifyPayload;

/**
 * Method label `passkey:<credential id>` for a base64url credential id.
 */
export function passkeyMethod(credential_id: string): string;

/**
 * Wrapping key (32 bytes) of a `passkey:<credential id>` entry from the 32-byte WebAuthn PRF output.
 */
export function passkeyWrappingKey(prf_output: Uint8Array): Uint8Array;

/**
 * Safety number of two users (60 digits; display as 12 groups of 5). Argument order is irrelevant.
 */
export function safetyNumber(address_a: string, key_a: Uint8Array, address_b: string, key_b: Uint8Array): string;

/**
 * Seals the fresh key of a history share v2 to one recipient device's share public key (ENCRYPTION.md §7b).
 */
export function sealShareKey(share_public_key: Uint8Array, key: Uint8Array): Uint8Array;

/**
 * libsodium `crypto_box_seal` to an inbox public key: what a webhook sender does (ENCRYPTION.md §5b).
 */
export function sealToInbox(public_key: Uint8Array, plaintext: Uint8Array): Uint8Array;

/**
 * The input to pass as `extensions.prf.eval.first` in every WebAuthn ceremony.
 */
export function secretStoragePrfInput(): Uint8Array;

/**
 * The X25519 public key of a share secret key.
 */
export function sharePublicKey(share_secret_key: Uint8Array): Uint8Array;

/**
 * Signs the continuity statement `old → new` at `at` (RFC 3339) with both keys; returns its JSON
 * `{ old_key, new_key, at, sig_old, sig_new }`.
 */
export function signContinuity(old: IdentityKey, _new: IdentityKey, at: string): string;

/**
 * Unwraps an `identity_blob`; the caller checks the public key against the published one.
 */
export function unwrapIdentityKey(master: MasterSecret, blob: Uint8Array, user_address: string): IdentityKey;

/**
 * Unwraps a secret storage entry fetched from the home node.
 */
export function unwrapMasterSecret(wrapped: Uint8Array, wrapping_key: Uint8Array, user_address: string, method: string): MasterSecret;

/**
 * Checks both signatures of one statement (JSON); false for anything malformed.
 */
export function verifyContinuity(statement_json: string): boolean;

/**
 * Checks an identity signature over a device key against the trusted (pinned) identity key.
 */
export function verifyDeviceAttestation(user_address: string, device_id: string, device_public_key: Uint8Array, signature: Uint8Array, trusted_identity_key: Uint8Array): boolean;

/**
 * Checks a device's published share key against its (verified) device key (ENCRYPTION.md §3.1): clients seal
 * nothing to a share key whose signature does not verify.
 */
export function verifyDeviceShareKey(device_id: string, device_public_key: Uint8Array, share_public_key: Uint8Array, signature: Uint8Array): boolean;

/**
 * QR payload `tavrn:verify?v=1&a=…&ka=…&b=…&kb=…` of two users.
 */
export function verifyPayload(address_a: string, key_a: Uint8Array, address_b: string, key_b: Uint8Array): string;

/**
 * True if the payload names exactly the own address with the own key and the contact with the
 * pinned key (FEDERATION.md §10.1).
 */
export function verifyPayloadMatches(text: string, own_address: string, own_key: Uint8Array, contact_address: string, contact_key: Uint8Array): boolean;

/**
 * Verifies the `signature` of a plaintext message. `fieldsJson` holds the envelope fields
 * (`conversation`, `author`, `device_id`, `reply_to`, `thread_id`, `mentions_everyone`, `mentions`,
 * `attachments`), `contentJcs` the content object in RFC 8785 form (checked against this
 * implementation). Returns false for a wrong signature; throws for malformed input.
 */
export function verifyPlaintext(fields_json: string, content_jcs: string, signature: string, device_public_key: Uint8Array): boolean;

/**
 * Wraps a rotated identity key for the home node (`identity_blob`, 61 bytes).
 */
export function wrapIdentityKey(master: MasterSecret, key: IdentityKey, user_address: string): Uint8Array;

/**
 * Wraps the master secret for the secret storage method `method` (`recovery` or
 * `passkey:<credential id>`) of `userAddress`; returns the bytes to upload (base64url).
 */
export function wrapMasterSecret(master: MasterSecret, wrapping_key: Uint8Array, user_address: string, method: string): Uint8Array;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_client_free: (a: number, b: number) => void;
    readonly __wbg_commitoutput_free: (a: number, b: number) => void;
    readonly __wbg_encryptedfile_free: (a: number, b: number) => void;
    readonly __wbg_encryptedshare_free: (a: number, b: number) => void;
    readonly __wbg_get_commitoutput_commit: (a: number, b: number) => void;
    readonly __wbg_get_commitoutput_epoch: (a: number) => number;
    readonly __wbg_get_commitoutput_groupInfo: (a: number, b: number) => void;
    readonly __wbg_get_commitoutput_welcome: (a: number, b: number) => void;
    readonly __wbg_get_encryptedfile_ciphertext: (a: number, b: number) => void;
    readonly __wbg_get_encryptedfile_key: (a: number, b: number) => void;
    readonly __wbg_get_encryptedfile_nonce: (a: number, b: number) => void;
    readonly __wbg_get_encryptedfile_sha256: (a: number, b: number) => void;
    readonly __wbg_get_encryptedshare_content: (a: number, b: number) => void;
    readonly __wbg_get_encryptedshare_epoch: (a: number) => number;
    readonly __wbg_get_encryptedshare_key: (a: number, b: number) => void;
    readonly __wbg_get_handshakeoutcome_added: (a: number, b: number) => void;
    readonly __wbg_get_handshakeoutcome_committer: (a: number, b: number) => void;
    readonly __wbg_get_handshakeoutcome_discardedPendingCommit: (a: number) => number;
    readonly __wbg_get_handshakeoutcome_epoch: (a: number) => number;
    readonly __wbg_get_handshakeoutcome_externalJoin: (a: number) => number;
    readonly __wbg_get_handshakeoutcome_removed: (a: number, b: number) => void;
    readonly __wbg_get_handshakeoutcome_selfRemoved: (a: number) => number;
    readonly __wbg_get_inboxkey_publicKey: (a: number, b: number) => void;
    readonly __wbg_get_inboxkey_signature: (a: number, b: number) => void;
    readonly __wbg_get_rosterentry_identity: (a: number, b: number) => void;
    readonly __wbg_get_rosterentry_signatureKey: (a: number, b: number) => void;
    readonly __wbg_get_sharekey_publicKey: (a: number, b: number) => void;
    readonly __wbg_get_sharekey_signature: (a: number, b: number) => void;
    readonly __wbg_get_verifypayload_a: (a: number, b: number) => void;
    readonly __wbg_get_verifypayload_b: (a: number, b: number) => void;
    readonly __wbg_get_verifypayload_ka: (a: number, b: number) => void;
    readonly __wbg_get_verifypayload_kb: (a: number, b: number) => void;
    readonly __wbg_get_welcomejoin_conversation: (a: number, b: number) => void;
    readonly __wbg_get_welcomejoin_epoch: (a: number) => number;
    readonly __wbg_handshakeoutcome_free: (a: number, b: number) => void;
    readonly __wbg_identitykey_free: (a: number, b: number) => void;
    readonly __wbg_inboxkey_free: (a: number, b: number) => void;
    readonly __wbg_mastersecret_free: (a: number, b: number) => void;
    readonly __wbg_recoverykey_free: (a: number, b: number) => void;
    readonly __wbg_rosterentry_free: (a: number, b: number) => void;
    readonly __wbg_set_commitoutput_commit: (a: number, b: number, c: number) => void;
    readonly __wbg_set_commitoutput_epoch: (a: number, b: number) => void;
    readonly __wbg_set_commitoutput_groupInfo: (a: number, b: number, c: number) => void;
    readonly __wbg_set_commitoutput_welcome: (a: number, b: number, c: number) => void;
    readonly __wbg_set_encryptedfile_ciphertext: (a: number, b: number, c: number) => void;
    readonly __wbg_set_encryptedfile_key: (a: number, b: number, c: number) => void;
    readonly __wbg_set_encryptedfile_nonce: (a: number, b: number, c: number) => void;
    readonly __wbg_set_encryptedfile_sha256: (a: number, b: number, c: number) => void;
    readonly __wbg_set_encryptedshare_content: (a: number, b: number, c: number) => void;
    readonly __wbg_set_encryptedshare_epoch: (a: number, b: number) => void;
    readonly __wbg_set_encryptedshare_key: (a: number, b: number, c: number) => void;
    readonly __wbg_set_handshakeoutcome_added: (a: number, b: number, c: number) => void;
    readonly __wbg_set_handshakeoutcome_committer: (a: number, b: number, c: number) => void;
    readonly __wbg_set_handshakeoutcome_discardedPendingCommit: (a: number, b: number) => void;
    readonly __wbg_set_handshakeoutcome_epoch: (a: number, b: number) => void;
    readonly __wbg_set_handshakeoutcome_externalJoin: (a: number, b: number) => void;
    readonly __wbg_set_handshakeoutcome_removed: (a: number, b: number, c: number) => void;
    readonly __wbg_set_handshakeoutcome_selfRemoved: (a: number, b: number) => void;
    readonly __wbg_set_inboxkey_publicKey: (a: number, b: number, c: number) => void;
    readonly __wbg_set_inboxkey_signature: (a: number, b: number, c: number) => void;
    readonly __wbg_set_rosterentry_identity: (a: number, b: number, c: number) => void;
    readonly __wbg_set_rosterentry_signatureKey: (a: number, b: number, c: number) => void;
    readonly __wbg_set_sharekey_publicKey: (a: number, b: number, c: number) => void;
    readonly __wbg_set_sharekey_signature: (a: number, b: number, c: number) => void;
    readonly __wbg_set_verifypayload_a: (a: number, b: number, c: number) => void;
    readonly __wbg_set_verifypayload_b: (a: number, b: number, c: number) => void;
    readonly __wbg_set_verifypayload_ka: (a: number, b: number, c: number) => void;
    readonly __wbg_set_verifypayload_kb: (a: number, b: number, c: number) => void;
    readonly __wbg_set_welcomejoin_conversation: (a: number, b: number, c: number) => void;
    readonly __wbg_set_welcomejoin_epoch: (a: number, b: number) => void;
    readonly __wbg_sharekey_free: (a: number, b: number) => void;
    readonly __wbg_verifypayload_free: (a: number, b: number) => void;
    readonly __wbg_welcomejoin_free: (a: number, b: number) => void;
    readonly canonicalJson: (a: number, b: number, c: number) => void;
    readonly capability: (a: number) => void;
    readonly client_addMembers: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly client_create: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly client_createGroup: (a: number, b: number, c: number, d: number) => void;
    readonly client_createKeyPackage: (a: number, b: number) => void;
    readonly client_currentEpoch: (a: number, b: number, c: number, d: number) => void;
    readonly client_decryptContent: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => void;
    readonly client_deleteGroup: (a: number, b: number, c: number, d: number) => void;
    readonly client_deviceId: (a: number, b: number) => void;
    readonly client_devicePublicKey: (a: number, b: number) => void;
    readonly client_discardPendingCommit: (a: number, b: number, c: number, d: number) => void;
    readonly client_encryptContent: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly client_encryptShare: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly client_exportBackup: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly client_exportEpochKey: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly client_exportState: (a: number, b: number) => void;
    readonly client_exportVoiceKey: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly client_hasGroup: (a: number, b: number, c: number) => number;
    readonly client_identity: (a: number, b: number) => void;
    readonly client_importBackup: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => void;
    readonly client_importEpochKey: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly client_importState: (a: number, b: number, c: number) => void;
    readonly client_inboxKey: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly client_joinByExternalCommit: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly client_joinByWelcome: (a: number, b: number, c: number, d: number) => void;
    readonly client_knownEpochs: (a: number, b: number, c: number, d: number) => void;
    readonly client_mergePendingCommit: (a: number, b: number, c: number, d: number) => void;
    readonly client_openSealed: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly client_openShareBox: (a: number, b: number, c: number, d: number) => void;
    readonly client_processHandshake: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly client_removeMembers: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly client_roster: (a: number, b: number, c: number, d: number) => void;
    readonly client_selfUpdate: (a: number, b: number, c: number, d: number) => void;
    readonly client_shareKey: (a: number) => number;
    readonly client_signDeviceLogin: (a: number, b: number, c: number, d: number) => void;
    readonly client_signPlaintext: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly client_userAddress: (a: number, b: number) => void;
    readonly contentEpoch: (a: number, b: number, c: number) => void;
    readonly continuityReaches: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
    readonly decryptContentWithKey: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number) => void;
    readonly decryptFile: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
    readonly decryptScene: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
    readonly deviceShareSecretKey: (a: number, b: number, c: number) => void;
    readonly encryptFile: (a: number, b: number, c: number) => void;
    readonly encryptScene: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
    readonly identitykey_attestDevice: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => void;
    readonly identitykey_fromBytes: (a: number, b: number, c: number) => void;
    readonly identitykey_fromMaster: (a: number) => number;
    readonly identitykey_generate: (a: number) => void;
    readonly identitykey_publicKey: (a: number, b: number) => void;
    readonly identitykey_toBytes: (a: number, b: number) => void;
    readonly inboxPublicKey: (a: number, b: number, c: number) => void;
    readonly mastersecret_attestDevice: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => void;
    readonly mastersecret_backupKey: (a: number, b: number) => void;
    readonly mastersecret_fromBytes: (a: number, b: number, c: number) => void;
    readonly mastersecret_fromKeyFile: (a: number, b: number, c: number) => void;
    readonly mastersecret_generate: (a: number) => void;
    readonly mastersecret_identityPublicKey: (a: number, b: number) => void;
    readonly mastersecret_localStorageKey: (a: number, b: number, c: number, d: number) => void;
    readonly mastersecret_toBytes: (a: number, b: number) => void;
    readonly mastersecret_toKeyFile: (a: number, b: number, c: number, d: number) => void;
    readonly openShareBox: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly parseVerifyPayload: (a: number, b: number, c: number) => void;
    readonly passkeyMethod: (a: number, b: number, c: number) => void;
    readonly passkeyWrappingKey: (a: number, b: number, c: number) => void;
    readonly recoverykey_fromText: (a: number, b: number, c: number) => void;
    readonly recoverykey_generate: (a: number) => void;
    readonly recoverykey_toCompact: (a: number, b: number) => void;
    readonly recoverykey_toText: (a: number, b: number, c: number, d: number) => void;
    readonly recoverykey_toWords: (a: number, b: number) => void;
    readonly recoverykey_wrappingKey: (a: number, b: number) => void;
    readonly safetyNumber: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
    readonly sealShareKey: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly sealToInbox: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly secretStoragePrfInput: (a: number) => void;
    readonly sharePublicKey: (a: number, b: number, c: number) => void;
    readonly signContinuity: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly unwrapIdentityKey: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly unwrapMasterSecret: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
    readonly verifyContinuity: (a: number, b: number) => number;
    readonly verifyDeviceAttestation: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => number;
    readonly verifyDeviceShareKey: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
    readonly verifyPayload: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
    readonly verifyPayloadMatches: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => number;
    readonly verifyPlaintext: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
    readonly wrapIdentityKey: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly wrapMasterSecret: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => void;
    readonly __wbindgen_export: (a: number, b: number) => number;
    readonly __wbindgen_export2: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_export3: (a: number) => void;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_export4: (a: number, b: number, c: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
