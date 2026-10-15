/* @ts-self-types="./tavrn_crypto.d.ts" */

/**
 * The MLS client of this device. Persist `exportState()` after every mutating call.
 */
export class Client {
    static __wrap(ptr) {
        const obj = Object.create(Client.prototype);
        obj.__wbg_ptr = ptr;
        ClientFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        ClientFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_client_free(ptr, 0);
    }
    /**
     * @param {string} conversation
     * @param {Uint8Array[]} key_packages
     * @returns {CommitOutput}
     */
    addMembers(conversation, key_packages) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArrayJsValueToWasm0(key_packages, wasm.__wbindgen_export);
            const len1 = WASM_VECTOR_LEN;
            wasm.client_addMembers(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return CommitOutput.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Creates the group at epoch 0; returns its GroupInfo.
     * @param {string} conversation
     * @returns {Uint8Array}
     */
    createGroup(conversation) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_createGroup(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v2;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @returns {Uint8Array}
     */
    createKeyPackage() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.client_createKeyPackage(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * A new device: generates its Ed25519 key.
     * @param {string} user_address
     * @param {string} device_id
     * @returns {Client}
     */
    static create(user_address, device_id) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(user_address, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(device_id, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            wasm.client_create(retptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return Client.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {string} conversation
     * @returns {number}
     */
    currentEpoch(conversation) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_currentEpoch(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getFloat64(retptr + 8 * 0, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            return r0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Decrypts and verifies `content`. Pass `devicePublicKey` (from the verified attestation, ENCRYPTION.md §3.3)
     * whenever it is known: a leaf of the device in the local group with another key then fails with
     * `unknown_sender`. Without it the key of the device's leaf is used.
     * @param {string} conversation
     * @param {string} author
     * @param {string} device_id
     * @param {string} content
     * @param {Uint8Array | null} [device_public_key]
     * @returns {string}
     */
    decryptContent(conversation, author, device_id, content, device_public_key) {
        let deferred7_0;
        let deferred7_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(author, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passStringToWasm0(device_id, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len2 = WASM_VECTOR_LEN;
            const ptr3 = passStringToWasm0(content, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len3 = WASM_VECTOR_LEN;
            var ptr4 = isLikeNone(device_public_key) ? 0 : passArray8ToWasm0(device_public_key, wasm.__wbindgen_export);
            var len4 = WASM_VECTOR_LEN;
            wasm.client_decryptContent(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            var ptr6 = r0;
            var len6 = r1;
            if (r3) {
                ptr6 = 0; len6 = 0;
                throw takeObject(r2);
            }
            deferred7_0 = ptr6;
            deferred7_1 = len6;
            return getStringFromWasm0(ptr6, len6);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred7_0, deferred7_1, 1);
        }
    }
    /**
     * @param {string} conversation
     */
    deleteGroup(conversation) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_deleteGroup(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @returns {string}
     */
    get deviceId() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.client_deviceId(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Ed25519 device public key (32 bytes) = MLS leaf signature key.
     * @returns {Uint8Array}
     */
    get devicePublicKey() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.client_devicePublicKey(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {string} conversation
     */
    discardPendingCommit(conversation) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_discardPendingCommit(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Encrypts a JSON content object; returns the `content` value with the epoch it was encrypted for.
     * @param {string} conversation
     * @param {string} json
     * @returns {EncryptedContent}
     */
    encryptContentWithEpoch(conversation, json) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            wasm.client_encryptContentWithEpoch(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return EncryptedContent.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Encrypts a JSON content object; returns the base64url `content` value.
     * @param {string} conversation
     * @param {string} json
     * @returns {string}
     */
    encryptContent(conversation, json) {
        let deferred4_0;
        let deferred4_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            wasm.client_encryptContent(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            var ptr3 = r0;
            var len3 = r1;
            if (r3) {
                ptr3 = 0; len3 = 0;
                throw takeObject(r2);
            }
            deferred4_0 = ptr3;
            deferred4_1 = len3;
            return getStringFromWasm0(ptr3, len3);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred4_0, deferred4_1, 1);
        }
    }
    /**
     * A history share v2 (ENCRYPTION.md §7b): `json` encrypted and signed like content of the current epoch under a
     * fresh key, which is sealed to each of `share_public_keys` (verified share keys of the recipient's devices) and
     * then zeroed.
     * @param {string} conversation
     * @param {string} json
     * @param {Uint8Array[]} share_public_keys
     * @returns {EncryptedShare}
     */
    encryptShare(conversation, json, share_public_keys) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passArrayJsValueToWasm0(share_public_keys, wasm.__wbindgen_export);
            const len2 = WASM_VECTOR_LEN;
            wasm.client_encryptShare(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return EncryptedShare.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Encrypted history backup of one conversation (upload to the home node).
     * @param {string} conversation
     * @param {Uint8Array} backup_key
     * @returns {Uint8Array}
     */
    exportBackup(conversation, backup_key) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_exportBackup(retptr, this.__wbg_ptr, ptr0, len0, addBorrowedObject(backup_key));
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v2;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            heap[stack_pointer++] = undefined;
        }
    }
    /**
     * @param {string} conversation
     * @param {number} epoch
     * @returns {Uint8Array}
     */
    exportEpochKey(conversation, epoch) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_exportEpochKey(retptr, this.__wbg_ptr, ptr0, len0, epoch);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Serializes the whole client state (secret! wipe it after storing).
     * @returns {Uint8Array}
     */
    exportState() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.client_exportState(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Voice frame key of the current epoch (32 bytes, ENCRYPTION.md §5a) for LiveKit's key provider at
     * key index `epoch % 256`. Fails unless `epoch` is the group's current epoch.
     * @param {string} conversation
     * @param {number} epoch
     * @returns {Uint8Array}
     */
    exportVoiceKey(conversation, epoch) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_exportVoiceKey(retptr, this.__wbg_ptr, ptr0, len0, epoch);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {string} conversation
     * @returns {boolean}
     */
    hasGroup(conversation) {
        const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.client_hasGroup(this.__wbg_ptr, ptr0, len0);
        return ret !== 0;
    }
    /**
     * `<user>@<domain>/<device_id>`.
     * @returns {string}
     */
    get identity() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.client_identity(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Imports a history backup; returns the number of epoch keys in it.
     * @param {string} conversation
     * @param {Uint8Array} backup_key
     * @param {Uint8Array} blob
     * @returns {number}
     */
    importBackup(conversation, backup_key, blob) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(blob, wasm.__wbindgen_export);
            const len1 = WASM_VECTOR_LEN;
            wasm.client_importBackup(retptr, this.__wbg_ptr, ptr0, len0, addBorrowedObject(backup_key), ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return r0 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            heap[stack_pointer++] = undefined;
        }
    }
    /**
     * @param {string} conversation
     * @param {number} epoch
     * @param {Uint8Array} key
     */
    importEpochKey(conversation, epoch, key) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_importEpochKey(retptr, this.__wbg_ptr, ptr0, len0, epoch, addBorrowedObject(key));
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            heap[stack_pointer++] = undefined;
        }
    }
    /**
     * Restores a client from `exportState()` bytes (wipe them afterwards). Every group is loaded once:
     * `state_malformed` for a state whose groups do not load.
     * @param {Uint8Array} state
     * @returns {Client}
     */
    static importState(state) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.client_importState(retptr, addBorrowedObject(state));
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return Client.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            heap[stack_pointer++] = undefined;
        }
    }
    /**
     * The inbox public key of `epoch` with this device's signature (needs the epoch's content key).
     * @param {string} conversation
     * @param {number} epoch
     * @returns {InboxKey}
     */
    inboxKey(conversation, epoch) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_inboxKey(retptr, this.__wbg_ptr, ptr0, len0, epoch);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return InboxKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {string} conversation
     * @param {Uint8Array} group_info
     * @returns {CommitOutput}
     */
    joinByExternalCommit(conversation, group_info) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(group_info, wasm.__wbindgen_export);
            const len1 = WASM_VECTOR_LEN;
            wasm.client_joinByExternalCommit(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return CommitOutput.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {Uint8Array} welcome
     * @returns {WelcomeJoin}
     */
    joinByWelcome(welcome) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(welcome, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_joinByWelcome(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WelcomeJoin.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {string} conversation
     * @returns {Float64Array}
     */
    knownEpochs(conversation) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_knownEpochs(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v2 = getArrayF64FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 8, 8);
            return v2;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {string} conversation
     * @returns {number}
     */
    mergePendingCommit(conversation) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_mergePendingCommit(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getFloat64(retptr + 8 * 0, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            return r0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Opens a sealed webhook message of `epoch`; returns the inner JSON (`unknown_epoch` without the key).
     * @param {string} conversation
     * @param {number} epoch
     * @param {Uint8Array} sealed
     * @returns {string}
     */
    openSealed(conversation, epoch, sealed) {
        let deferred4_0;
        let deferred4_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(sealed, wasm.__wbindgen_export);
            const len1 = WASM_VECTOR_LEN;
            wasm.client_openSealed(retptr, this.__wbg_ptr, ptr0, len0, epoch, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            var ptr3 = r0;
            var len3 = r1;
            if (r3) {
                ptr3 = 0; len3 = 0;
                throw takeObject(r2);
            }
            deferred4_0 = ptr3;
            deferred4_1 = len3;
            return getStringFromWasm0(ptr3, len3);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred4_0, deferred4_1, 1);
        }
    }
    /**
     * Opens a sealed share key addressed to this device; returns the 32-byte key (`decryption_failed` otherwise).
     * @param {Uint8Array} sealed
     * @returns {Uint8Array}
     */
    openShareBox(sealed) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(sealed, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_openShareBox(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {string} conversation
     * @param {Uint8Array} message
     * @returns {HandshakeOutcome}
     */
    processHandshake(conversation, message) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_export);
            const len1 = WASM_VECTOR_LEN;
            wasm.client_processHandshake(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return HandshakeOutcome.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Removes leaves by identity and signature key (`identities[i]` with `signatureKeys[i]`): exactly that leaf,
     * also when another leaf names the same device.
     * @param {string} conversation
     * @param {string[]} identities
     * @param {Uint8Array[]} signature_keys
     * @returns {CommitOutput}
     */
    removeLeaves(conversation, identities, signature_keys) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArrayJsValueToWasm0(identities, wasm.__wbindgen_export);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passArrayJsValueToWasm0(signature_keys, wasm.__wbindgen_export);
            const len2 = WASM_VECTOR_LEN;
            wasm.client_removeLeaves(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return CommitOutput.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {string} conversation
     * @param {string[]} identities
     * @returns {CommitOutput}
     */
    removeMembers(conversation, identities) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArrayJsValueToWasm0(identities, wasm.__wbindgen_export);
            const len1 = WASM_VECTOR_LEN;
            wasm.client_removeMembers(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return CommitOutput.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {string} conversation
     * @returns {RosterEntry[]}
     */
    roster(conversation) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_roster(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v2 = getArrayJsValueFromWasm0(r0, r1);
            wasm.__wbindgen_export4(r0, r1 * 4, 4);
            return v2;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {string} conversation
     * @returns {CommitOutput}
     */
    selfUpdate(conversation) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_selfUpdate(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return CommitOutput.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * This device's share key and the device signature over it (ENCRYPTION.md §3.1).
     * @returns {ShareKey}
     */
    shareKey() {
        const ret = wasm.client_shareKey(this.__wbg_ptr);
        return ShareKey.__wrap(ret);
    }
    /**
     * Device login proof over the node's login nonce (ENCRYPTION.md §3.4), 64 bytes.
     * @param {string} nonce
     * @returns {Uint8Array}
     */
    signDeviceLogin(nonce) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(nonce, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.client_signDeviceLogin(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v2;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Signs a plaintext message with this device (FEDERATION.md §10.3); returns the envelope value
     * `signature`. `fieldsJson` as for `verifyPlaintext` (author and device must be this device's).
     * @param {string} fields_json
     * @param {string} content_jcs
     * @returns {string}
     */
    signPlaintext(fields_json, content_jcs) {
        let deferred4_0;
        let deferred4_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(fields_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(content_jcs, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            wasm.client_signPlaintext(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            var ptr3 = r0;
            var len3 = r1;
            if (r3) {
                ptr3 = 0; len3 = 0;
                throw takeObject(r2);
            }
            deferred4_0 = ptr3;
            deferred4_1 = len3;
            return getStringFromWasm0(ptr3, len3);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred4_0, deferred4_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get userAddress() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.client_userAddress(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
}
if (Symbol.dispose) Client.prototype[Symbol.dispose] = Client.prototype.free;

/**
 * Messages produced by a commit; see [`mls::CommitOutput`]. Each read of a property copies the bytes once.
 */
export class CommitOutput {
    static __wrap(ptr) {
        const obj = Object.create(CommitOutput.prototype);
        obj.__wbg_ptr = ptr;
        CommitOutputFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        CommitOutputFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_commitoutput_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    get commit() {
        const ret = wasm.commitoutput_commit(this.__wbg_ptr);
        return takeObject(ret);
    }
    /**
     * @returns {number}
     */
    get epoch() {
        const ret = wasm.commitoutput_epoch(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Uint8Array}
     */
    get groupInfo() {
        const ret = wasm.commitoutput_groupInfo(this.__wbg_ptr);
        return takeObject(ret);
    }
    /**
     * @returns {Uint8Array | undefined}
     */
    get welcome() {
        const ret = wasm.commitoutput_welcome(this.__wbg_ptr);
        return takeObject(ret);
    }
}
if (Symbol.dispose) CommitOutput.prototype[Symbol.dispose] = CommitOutput.prototype.free;

/**
 * A content value with the epoch it was encrypted for (the envelope's `epoch`).
 */
export class EncryptedContent {
    static __wrap(ptr) {
        const obj = Object.create(EncryptedContent.prototype);
        obj.__wbg_ptr = ptr;
        EncryptedContentFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        EncryptedContentFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_encryptedcontent_free(ptr, 0);
    }
    /**
     * @returns {string}
     */
    get content() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_encryptedcontent_content(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {number}
     */
    get epoch() {
        const ret = wasm.__wbg_get_encryptedcontent_epoch(this.__wbg_ptr);
        return ret;
    }
    /**
     * @param {string} arg0
     */
    set content(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_encryptedcontent_content(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {number} arg0
     */
    set epoch(arg0) {
        wasm.__wbg_set_encryptedcontent_epoch(this.__wbg_ptr, arg0);
    }
}
if (Symbol.dispose) EncryptedContent.prototype[Symbol.dispose] = EncryptedContent.prototype.free;

/**
 * An encrypted attachment: upload `ciphertext`, put `key`, `nonce`, `sha256` into the content.
 */
export class EncryptedFile {
    static __wrap(ptr) {
        const obj = Object.create(EncryptedFile.prototype);
        obj.__wbg_ptr = ptr;
        EncryptedFileFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        EncryptedFileFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_encryptedfile_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    get ciphertext() {
        const ret = wasm.encryptedfile_ciphertext(this.__wbg_ptr);
        return takeObject(ret);
    }
    /**
     * @returns {Uint8Array}
     */
    get key() {
        const ret = wasm.encryptedfile_key(this.__wbg_ptr);
        return takeObject(ret);
    }
    /**
     * @returns {Uint8Array}
     */
    get nonce() {
        const ret = wasm.encryptedfile_nonce(this.__wbg_ptr);
        return takeObject(ret);
    }
    /**
     * @returns {Uint8Array}
     */
    get sha256() {
        const ret = wasm.encryptedfile_sha256(this.__wbg_ptr);
        return takeObject(ret);
    }
}
if (Symbol.dispose) EncryptedFile.prototype[Symbol.dispose] = EncryptedFile.prototype.free;

/**
 * A history share v2: the content and the share key sealed to each recipient device, in the order of the share keys
 * passed to `Client.encryptShare` (the key itself never leaves the WebAssembly module).
 */
export class EncryptedShare {
    static __wrap(ptr) {
        const obj = Object.create(EncryptedShare.prototype);
        obj.__wbg_ptr = ptr;
        EncryptedShareFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        EncryptedShareFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_encryptedshare_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array[]}
     */
    get boxes() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_encryptedshare_boxes(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayJsValueFromWasm0(r0, r1);
            wasm.__wbindgen_export4(r0, r1 * 4, 4);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @returns {string}
     */
    get content() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_encryptedshare_content(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {number}
     */
    get epoch() {
        const ret = wasm.__wbg_get_encryptedshare_epoch(this.__wbg_ptr);
        return ret;
    }
    /**
     * @param {Uint8Array[]} arg0
     */
    set boxes(arg0) {
        const ptr0 = passArrayJsValueToWasm0(arg0, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_encryptedshare_boxes(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set content(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_encryptedshare_content(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {number} arg0
     */
    set epoch(arg0) {
        wasm.__wbg_set_encryptedshare_epoch(this.__wbg_ptr, arg0);
    }
}
if (Symbol.dispose) EncryptedShare.prototype[Symbol.dispose] = EncryptedShare.prototype.free;

/**
 * Result of processing a commit; see [`mls::HandshakeOutcome`].
 */
export class HandshakeOutcome {
    static __wrap(ptr) {
        const obj = Object.create(HandshakeOutcome.prototype);
        obj.__wbg_ptr = ptr;
        HandshakeOutcomeFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        HandshakeOutcomeFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_handshakeoutcome_free(ptr, 0);
    }
    /**
     * @returns {string[]}
     */
    get added() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_handshakeoutcome_added(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayJsValueFromWasm0(r0, r1);
            wasm.__wbindgen_export4(r0, r1 * 4, 4);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @returns {string}
     */
    get committer() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_handshakeoutcome_committer(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {boolean}
     */
    get discardedPendingCommit() {
        const ret = wasm.__wbg_get_handshakeoutcome_discardedPendingCommit(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * @returns {number}
     */
    get epoch() {
        const ret = wasm.__wbg_get_handshakeoutcome_epoch(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {boolean}
     */
    get externalJoin() {
        const ret = wasm.__wbg_get_handshakeoutcome_externalJoin(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * @returns {string[]}
     */
    get removed() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_handshakeoutcome_removed(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayJsValueFromWasm0(r0, r1);
            wasm.__wbindgen_export4(r0, r1 * 4, 4);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @returns {boolean}
     */
    get selfRemoved() {
        const ret = wasm.__wbg_get_handshakeoutcome_selfRemoved(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * @param {string[]} arg0
     */
    set added(arg0) {
        const ptr0 = passArrayJsValueToWasm0(arg0, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_handshakeoutcome_added(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set committer(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_handshakeoutcome_committer(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {boolean} arg0
     */
    set discardedPendingCommit(arg0) {
        wasm.__wbg_set_handshakeoutcome_discardedPendingCommit(this.__wbg_ptr, arg0);
    }
    /**
     * @param {number} arg0
     */
    set epoch(arg0) {
        wasm.__wbg_set_handshakeoutcome_epoch(this.__wbg_ptr, arg0);
    }
    /**
     * @param {boolean} arg0
     */
    set externalJoin(arg0) {
        wasm.__wbg_set_handshakeoutcome_externalJoin(this.__wbg_ptr, arg0);
    }
    /**
     * @param {string[]} arg0
     */
    set removed(arg0) {
        const ptr0 = passArrayJsValueToWasm0(arg0, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_handshakeoutcome_removed(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {boolean} arg0
     */
    set selfRemoved(arg0) {
        wasm.__wbg_set_handshakeoutcome_selfRemoved(this.__wbg_ptr, arg0);
    }
}
if (Symbol.dispose) HandshakeOutcome.prototype[Symbol.dispose] = HandshakeOutcome.prototype.free;

/**
 * An identity signing key of any generation (derived from the master secret, or rotated).
 */
export class IdentityKey {
    static __wrap(ptr) {
        const obj = Object.create(IdentityKey.prototype);
        obj.__wbg_ptr = ptr;
        IdentityKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        IdentityKeyFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_identitykey_free(ptr, 0);
    }
    /**
     * Signs a device public key with this identity key; returns the 64-byte signature.
     * @param {string} user_address
     * @param {string} device_id
     * @param {Uint8Array} device_public_key
     * @returns {Uint8Array}
     */
    attestDevice(user_address, device_id, device_public_key) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(user_address, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(device_id, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passArray8ToWasm0(device_public_key, wasm.__wbindgen_export);
            const len2 = WASM_VECTOR_LEN;
            wasm.identitykey_attestDevice(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v4 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v4;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * From the 32-byte seed (local secure storage only).
     * @param {Uint8Array} bytes
     * @returns {IdentityKey}
     */
    static fromBytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.identitykey_fromBytes(retptr, addBorrowedObject(bytes));
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return IdentityKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            heap[stack_pointer++] = undefined;
        }
    }
    /**
     * Generation 0: the key derived from the master secret.
     * @param {MasterSecret} master
     * @returns {IdentityKey}
     */
    static fromMaster(master) {
        _assertClass(master, MasterSecret);
        const ret = wasm.identitykey_fromMaster(master.__wbg_ptr);
        return IdentityKey.__wrap(ret);
    }
    /**
     * A fresh random identity key (rotation).
     * @returns {IdentityKey}
     */
    static generate() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.identitykey_generate(retptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return IdentityKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Ed25519 public identity key (32 bytes).
     * @returns {Uint8Array}
     */
    publicKey() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.identitykey_publicKey(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * The 32-byte seed (local secure storage only).
     * @returns {Uint8Array}
     */
    toBytes() {
        const ret = wasm.identitykey_toBytes(this.__wbg_ptr);
        return takeObject(ret);
    }
}
if (Symbol.dispose) IdentityKey.prototype[Symbol.dispose] = IdentityKey.prototype.free;

/**
 * A published inbox key: `PUT /conversations/{id}/inbox-key` (ENCRYPTION.md §5b).
 */
export class InboxKey {
    static __wrap(ptr) {
        const obj = Object.create(InboxKey.prototype);
        obj.__wbg_ptr = ptr;
        InboxKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        InboxKeyFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_inboxkey_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    get publicKey() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_inboxkey_publicKey(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @returns {Uint8Array}
     */
    get signature() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_inboxkey_signature(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {Uint8Array} arg0
     */
    set publicKey(arg0) {
        const ptr0 = passArray8ToWasm0(arg0, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_inboxkey_publicKey(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {Uint8Array} arg0
     */
    set signature(arg0) {
        const ptr0 = passArray8ToWasm0(arg0, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_inboxkey_signature(this.__wbg_ptr, ptr0, len0);
    }
}
if (Symbol.dispose) InboxKey.prototype[Symbol.dispose] = InboxKey.prototype.free;

/**
 * The account master secret.
 */
export class MasterSecret {
    static __wrap(ptr) {
        const obj = Object.create(MasterSecret.prototype);
        obj.__wbg_ptr = ptr;
        MasterSecretFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        MasterSecretFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_mastersecret_free(ptr, 0);
    }
    /**
     * Signs a device public key with the identity key; returns the 64-byte signature.
     * @param {string} user_address
     * @param {string} device_id
     * @param {Uint8Array} device_public_key
     * @returns {Uint8Array}
     */
    attestDevice(user_address, device_id, device_public_key) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(user_address, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(device_id, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passArray8ToWasm0(device_public_key, wasm.__wbindgen_export);
            const len2 = WASM_VECTOR_LEN;
            wasm.mastersecret_attestDevice(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v4 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v4;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * AES-256 backup key (32 bytes) for history backups.
     * @returns {Uint8Array}
     */
    backupKey() {
        const ret = wasm.mastersecret_backupKey(this.__wbg_ptr);
        return takeObject(ret);
    }
    /**
     * Restores from the 32 raw bytes (local secure storage only).
     * @param {Uint8Array} bytes
     * @returns {MasterSecret}
     */
    static fromBytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.mastersecret_fromBytes(retptr, addBorrowedObject(bytes));
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return MasterSecret.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            heap[stack_pointer++] = undefined;
        }
    }
    /**
     * Parses a key file, its `key:` value or its 24-word list.
     * @param {string} text
     * @returns {MasterSecret}
     */
    static fromKeyFile(text) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(text, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.mastersecret_fromKeyFile(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return MasterSecret.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * A new random master secret (registration, identity reset).
     * @returns {MasterSecret}
     */
    static generate() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.mastersecret_generate(retptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return MasterSecret.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Ed25519 public identity key (32 bytes), published by the home node.
     * @returns {Uint8Array}
     */
    identityPublicKey() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.mastersecret_identityPublicKey(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * AES-256 key (32 bytes) for the client's local crypto storage of device `deviceId`.
     * @param {string} device_id
     * @returns {Uint8Array}
     */
    localStorageKey(device_id) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(device_id, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.mastersecret_localStorageKey(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * The 32 raw bytes (local secure storage only).
     * @returns {Uint8Array}
     */
    toBytes() {
        const ret = wasm.mastersecret_toBytes(this.__wbg_ptr);
        return takeObject(ret);
    }
    /**
     * Text of the key file `tavrn-key-<username>.txt` for `account` (`user@domain`).
     * @param {string} account
     * @returns {string}
     */
    toKeyFile(account) {
        let deferred3_0;
        let deferred3_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(account, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.mastersecret_toKeyFile(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            var ptr2 = r0;
            var len2 = r1;
            if (r3) {
                ptr2 = 0; len2 = 0;
                throw takeObject(r2);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred3_0, deferred3_1, 1);
        }
    }
}
if (Symbol.dispose) MasterSecret.prototype[Symbol.dispose] = MasterSecret.prototype.free;

/**
 * The recovery key that unlocks the secret storage entry `recovery` (ENCRYPTION.md §2.4).
 */
export class RecoveryKey {
    static __wrap(ptr) {
        const obj = Object.create(RecoveryKey.prototype);
        obj.__wbg_ptr = ptr;
        RecoveryKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        RecoveryKeyFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_recoverykey_free(ptr, 0);
    }
    /**
     * Parses the 24 words, the compact string or a downloaded recovery key file.
     * @param {string} text
     * @returns {RecoveryKey}
     */
    static fromText(text) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(text, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.recoverykey_fromText(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return RecoveryKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * A new random recovery key (registration or regeneration).
     * @returns {RecoveryKey}
     */
    static generate() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.recoverykey_generate(retptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return RecoveryKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * The compact string (base64url with version byte and checksum).
     * @returns {string}
     */
    toCompact() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.recoverykey_toCompact(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Text of the optional download `tavrn-recovery-<username>.txt` for `account` (`user@domain`).
     * @param {string} account
     * @returns {string}
     */
    toText(account) {
        let deferred3_0;
        let deferred3_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(account, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.recoverykey_toText(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            var ptr2 = r0;
            var len2 = r1;
            if (r3) {
                ptr2 = 0; len2 = 0;
                throw takeObject(r2);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * The 24 words shown to the user.
     * @returns {string}
     */
    toWords() {
        let deferred2_0;
        let deferred2_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.recoverykey_toWords(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            var ptr1 = r0;
            var len1 = r1;
            if (r3) {
                ptr1 = 0; len1 = 0;
                throw takeObject(r2);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * AES-256 wrapping key (32 bytes) of the `recovery` method.
     * @returns {Uint8Array}
     */
    wrappingKey() {
        const ret = wasm.recoverykey_wrappingKey(this.__wbg_ptr);
        return takeObject(ret);
    }
}
if (Symbol.dispose) RecoveryKey.prototype[Symbol.dispose] = RecoveryKey.prototype.free;

/**
 * A member leaf of a group.
 */
export class RosterEntry {
    static __wrap(ptr) {
        const obj = Object.create(RosterEntry.prototype);
        obj.__wbg_ptr = ptr;
        RosterEntryFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        RosterEntryFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_rosterentry_free(ptr, 0);
    }
    /**
     * @returns {string}
     */
    get identity() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.rosterentry_identity(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {Uint8Array}
     */
    get signatureKey() {
        const ret = wasm.rosterentry_signatureKey(this.__wbg_ptr);
        return takeObject(ret);
    }
}
if (Symbol.dispose) RosterEntry.prototype[Symbol.dispose] = RosterEntry.prototype.free;

/**
 * A device's share key with the device signature over it (`PUT /users/me/devices/{id}/share-key`).
 */
export class ShareKey {
    static __wrap(ptr) {
        const obj = Object.create(ShareKey.prototype);
        obj.__wbg_ptr = ptr;
        ShareKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        ShareKeyFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_sharekey_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    get publicKey() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_sharekey_publicKey(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @returns {Uint8Array}
     */
    get signature() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_sharekey_signature(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {Uint8Array} arg0
     */
    set publicKey(arg0) {
        const ptr0 = passArray8ToWasm0(arg0, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_sharekey_publicKey(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {Uint8Array} arg0
     */
    set signature(arg0) {
        const ptr0 = passArray8ToWasm0(arg0, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_sharekey_signature(this.__wbg_ptr, ptr0, len0);
    }
}
if (Symbol.dispose) ShareKey.prototype[Symbol.dispose] = ShareKey.prototype.free;

/**
 * A parsed QR payload; keys are base64url.
 */
export class VerifyPayload {
    static __wrap(ptr) {
        const obj = Object.create(VerifyPayload.prototype);
        obj.__wbg_ptr = ptr;
        VerifyPayloadFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        VerifyPayloadFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_verifypayload_free(ptr, 0);
    }
    /**
     * @returns {string}
     */
    get a() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_verifypayload_a(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get b() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_verifypayload_b(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get ka() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_verifypayload_ka(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get kb() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_verifypayload_kb(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @param {string} arg0
     */
    set a(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_verifypayload_a(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set b(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_verifypayload_b(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set ka(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_verifypayload_ka(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set kb(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_verifypayload_kb(this.__wbg_ptr, ptr0, len0);
    }
}
if (Symbol.dispose) VerifyPayload.prototype[Symbol.dispose] = VerifyPayload.prototype.free;

/**
 * Result of joining by Welcome.
 */
export class WelcomeJoin {
    static __wrap(ptr) {
        const obj = Object.create(WelcomeJoin.prototype);
        obj.__wbg_ptr = ptr;
        WelcomeJoinFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WelcomeJoinFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_welcomejoin_free(ptr, 0);
    }
    /**
     * @returns {string}
     */
    get conversation() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_welcomejoin_conversation(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {number}
     */
    get epoch() {
        const ret = wasm.__wbg_get_welcomejoin_epoch(this.__wbg_ptr);
        return ret;
    }
    /**
     * @param {string} arg0
     */
    set conversation(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_welcomejoin_conversation(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {number} arg0
     */
    set epoch(arg0) {
        wasm.__wbg_set_welcomejoin_epoch(this.__wbg_ptr, arg0);
    }
}
if (Symbol.dispose) WelcomeJoin.prototype[Symbol.dispose] = WelcomeJoin.prototype.free;

/**
 * RFC 8785 (JCS) form of a JSON text.
 * @param {string} json
 * @returns {string}
 */
export function canonicalJson(json) {
    let deferred3_0;
    let deferred3_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        wasm.canonicalJson(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr2 = r0;
        var len2 = r1;
        if (r3) {
            ptr2 = 0; len2 = 0;
            throw takeObject(r2);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Capability string of this scheme (`e2ee.mls1`).
 * @returns {string}
 */
export function capability() {
    let deferred1_0;
    let deferred1_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.capability(retptr);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        deferred1_0 = r0;
        deferred1_1 = r1;
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
    }
}

/**
 * Epoch from the plaintext header of an encrypted `content` value.
 * @param {string} content_b64
 * @returns {number}
 */
export function contentEpoch(content_b64) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(content_b64, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        wasm.contentEpoch(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getFloat64(retptr + 8 * 0, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        return r0;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * The keys that lead to `current` through valid consecutive statements of `chain` (JSON array, oldest first),
 * `current` included; every statement is verified at most once. Only `current` for a malformed chain.
 * @param {string} chain_json
 * @param {string} current
 * @returns {string[]}
 */
export function continuityKeys(chain_json, current) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(chain_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(current, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        wasm.continuityKeys(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var v3 = getArrayJsValueFromWasm0(r0, r1);
        wasm.__wbindgen_export4(r0, r1 * 4, 4);
        return v3;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Is `to` reachable from `from` through valid consecutive statements of `chain` (JSON array, oldest first)?
 * @param {string} chain_json
 * @param {string} from
 * @param {string} to
 * @returns {boolean}
 */
export function continuityReaches(chain_json, from, to) {
    const ptr0 = passStringToWasm0(chain_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(from, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(to, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.continuityReaches(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret !== 0;
}

/**
 * Decrypts content format 1 under an explicit key (a history share v2 under the key from its box) and verifies the
 * device signature; nothing is stored.
 * @param {Uint8Array} key
 * @param {string} conversation
 * @param {string} author
 * @param {string} device_id
 * @param {string} content
 * @param {Uint8Array} device_public_key
 * @returns {string}
 */
export function decryptContentWithKey(key, conversation, author, device_id, content, device_public_key) {
    let deferred7_0;
    let deferred7_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(conversation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(author, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(device_id, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(content, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passArray8ToWasm0(device_public_key, wasm.__wbindgen_export);
        const len4 = WASM_VECTOR_LEN;
        wasm.decryptContentWithKey(retptr, addBorrowedObject(key), ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr6 = r0;
        var len6 = r1;
        if (r3) {
            ptr6 = 0; len6 = 0;
            throw takeObject(r2);
        }
        deferred7_0 = ptr6;
        deferred7_1 = len6;
        return getStringFromWasm0(ptr6, len6);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        heap[stack_pointer++] = undefined;
        wasm.__wbindgen_export4(deferred7_0, deferred7_1, 1);
    }
}

/**
 * Checks the ciphertext hash and decrypts an attachment.
 * @param {Uint8Array} ciphertext
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {Uint8Array} sha256
 * @returns {Uint8Array}
 */
export function decryptFile(ciphertext, key, nonce, sha256) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(nonce, wasm.__wbindgen_export);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(sha256, wasm.__wbindgen_export);
        const len2 = WASM_VECTOR_LEN;
        wasm.decryptFile(retptr, ptr0, len0, addBorrowedObject(key), ptr1, len1, ptr2, len2);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v4 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export4(r0, r1 * 1, 1);
        return v4;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        heap[stack_pointer++] = undefined;
    }
}

/**
 * Decrypts one part of a whiteboard scene.
 * @param {Uint8Array} backup_key
 * @param {string} scene_id
 * @param {string} part
 * @param {Uint8Array} blob
 * @returns {Uint8Array}
 */
export function decryptScene(backup_key, scene_id, part, blob) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(scene_id, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(part, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(blob, wasm.__wbindgen_export);
        const len2 = WASM_VECTOR_LEN;
        wasm.decryptScene(retptr, addBorrowedObject(backup_key), ptr0, len0, ptr1, len1, ptr2, len2);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v4 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export4(r0, r1 * 1, 1);
        return v4;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        heap[stack_pointer++] = undefined;
    }
}

/**
 * The share secret key a device derives from its device secret (ENCRYPTION.md §3.1; test vectors and tools, clients
 * use `Client.shareKey` and `Client.openShareBox`).
 * @param {Uint8Array} device_secret_key
 * @returns {Uint8Array}
 */
export function deviceShareSecretKey(device_secret_key) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.deviceShareSecretKey(retptr, addBorrowedObject(device_secret_key));
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        heap[stack_pointer++] = undefined;
    }
}

/**
 * Encrypts a file with a fresh random key (AES-256-GCM, one shot).
 * @param {Uint8Array} plaintext
 * @returns {EncryptedFile}
 */
export function encryptFile(plaintext) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(plaintext, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        wasm.encryptFile(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return EncryptedFile.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Encrypts one part (`"scene"` or `"thumbnail"`) of a whiteboard scene under the backup key
 * (`protocol/WHITEBOARD.md` §5).
 * @param {Uint8Array} backup_key
 * @param {string} scene_id
 * @param {string} part
 * @param {Uint8Array} plaintext
 * @returns {Uint8Array}
 */
export function encryptScene(backup_key, scene_id, part, plaintext) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(scene_id, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(part, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(plaintext, wasm.__wbindgen_export);
        const len2 = WASM_VECTOR_LEN;
        wasm.encryptScene(retptr, addBorrowedObject(backup_key), ptr0, len0, ptr1, len1, ptr2, len2);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v4 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export4(r0, r1 * 1, 1);
        return v4;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        heap[stack_pointer++] = undefined;
    }
}

/**
 * Inbox public key of write-only webhooks for the epoch whose content key is `content_key` (ENCRYPTION.md §5b;
 * test vectors and tools, clients use `Client.inboxKey`).
 * @param {Uint8Array} content_key
 * @returns {Uint8Array}
 */
export function inboxPublicKey(content_key) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(content_key, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        wasm.inboxPublicKey(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v2 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export4(r0, r1 * 1, 1);
        return v2;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Opens a sealed share key with a raw share secret key (test vectors and tools; clients use `Client.openShareBox`).
 * @param {Uint8Array} share_secret_key
 * @param {Uint8Array} sealed
 * @returns {Uint8Array}
 */
export function openShareBox(share_secret_key, sealed) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(sealed, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        wasm.openShareBox(retptr, addBorrowedObject(share_secret_key), ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        heap[stack_pointer++] = undefined;
    }
}

/**
 * Parses a QR payload strictly (throws `invalid_input` for anything malformed).
 * @param {string} text
 * @returns {VerifyPayload}
 */
export function parseVerifyPayload(text) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(text, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        wasm.parseVerifyPayload(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return VerifyPayload.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Method label `passkey:<credential id>` for a base64url credential id.
 * @param {string} credential_id
 * @returns {string}
 */
export function passkeyMethod(credential_id) {
    let deferred3_0;
    let deferred3_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(credential_id, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        wasm.passkeyMethod(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr2 = r0;
        var len2 = r1;
        if (r3) {
            ptr2 = 0; len2 = 0;
            throw takeObject(r2);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Wrapping key (32 bytes) of a `passkey:<credential id>` entry from the 32-byte WebAuthn PRF output.
 * @param {Uint8Array} prf_output
 * @returns {Uint8Array}
 */
export function passkeyWrappingKey(prf_output) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.passkeyWrappingKey(retptr, addBorrowedObject(prf_output));
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return takeObject(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        heap[stack_pointer++] = undefined;
    }
}

/**
 * Safety number of two users (60 digits; display as 12 groups of 5). Argument order is irrelevant.
 * @param {string} address_a
 * @param {Uint8Array} key_a
 * @param {string} address_b
 * @param {Uint8Array} key_b
 * @returns {string}
 */
export function safetyNumber(address_a, key_a, address_b, key_b) {
    let deferred6_0;
    let deferred6_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(address_a, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(key_a, wasm.__wbindgen_export);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(address_b, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(key_b, wasm.__wbindgen_export);
        const len3 = WASM_VECTOR_LEN;
        wasm.safetyNumber(retptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr5 = r0;
        var len5 = r1;
        if (r3) {
            ptr5 = 0; len5 = 0;
            throw takeObject(r2);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred6_0, deferred6_1, 1);
    }
}

/**
 * Seals the fresh key of a history share v2 to one recipient device's share public key (ENCRYPTION.md §7b).
 * @param {Uint8Array} share_public_key
 * @param {Uint8Array} key
 * @returns {Uint8Array}
 */
export function sealShareKey(share_public_key, key) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(share_public_key, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(key, wasm.__wbindgen_export);
        const len1 = WASM_VECTOR_LEN;
        wasm.sealShareKey(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v3 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export4(r0, r1 * 1, 1);
        return v3;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * libsodium `crypto_box_seal` to an inbox public key: what a webhook sender does (ENCRYPTION.md §5b).
 * @param {Uint8Array} public_key
 * @param {Uint8Array} plaintext
 * @returns {Uint8Array}
 */
export function sealToInbox(public_key, plaintext) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(public_key, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(plaintext, wasm.__wbindgen_export);
        const len1 = WASM_VECTOR_LEN;
        wasm.sealToInbox(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v3 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export4(r0, r1 * 1, 1);
        return v3;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * The input to pass as `extensions.prf.eval.first` in every WebAuthn ceremony.
 * @returns {Uint8Array}
 */
export function secretStoragePrfInput() {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.secretStoragePrfInput(retptr);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var v1 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export4(r0, r1 * 1, 1);
        return v1;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * The X25519 public key of a share secret key.
 * @param {Uint8Array} share_secret_key
 * @returns {Uint8Array}
 */
export function sharePublicKey(share_secret_key) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.sharePublicKey(retptr, addBorrowedObject(share_secret_key));
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v1 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export4(r0, r1 * 1, 1);
        return v1;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        heap[stack_pointer++] = undefined;
    }
}

/**
 * Signs the continuity statement `old → new` at `at` (RFC 3339) with both keys; returns its JSON
 * `{ old_key, new_key, at, sig_old, sig_new }`.
 * @param {IdentityKey} old
 * @param {IdentityKey} _new
 * @param {string} at
 * @returns {string}
 */
export function signContinuity(old, _new, at) {
    let deferred3_0;
    let deferred3_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(old, IdentityKey);
        _assertClass(_new, IdentityKey);
        const ptr0 = passStringToWasm0(at, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        wasm.signContinuity(retptr, old.__wbg_ptr, _new.__wbg_ptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr2 = r0;
        var len2 = r1;
        if (r3) {
            ptr2 = 0; len2 = 0;
            throw takeObject(r2);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Unwraps an `identity_blob`; the caller checks the public key against the published one.
 * @param {MasterSecret} master
 * @param {Uint8Array} blob
 * @param {string} user_address
 * @returns {IdentityKey}
 */
export function unwrapIdentityKey(master, blob, user_address) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(master, MasterSecret);
        const ptr0 = passArray8ToWasm0(blob, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(user_address, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        wasm.unwrapIdentityKey(retptr, master.__wbg_ptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return IdentityKey.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Unwraps a secret storage entry fetched from the home node.
 * @param {Uint8Array} wrapped
 * @param {Uint8Array} wrapping_key
 * @param {string} user_address
 * @param {string} method
 * @returns {MasterSecret}
 */
export function unwrapMasterSecret(wrapped, wrapping_key, user_address, method) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(wrapped, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(user_address, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(method, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len2 = WASM_VECTOR_LEN;
        wasm.unwrapMasterSecret(retptr, ptr0, len0, addBorrowedObject(wrapping_key), ptr1, len1, ptr2, len2);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return MasterSecret.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        heap[stack_pointer++] = undefined;
    }
}

/**
 * Checks both signatures of one statement (JSON); false for anything malformed.
 * @param {string} statement_json
 * @returns {boolean}
 */
export function verifyContinuity(statement_json) {
    const ptr0 = passStringToWasm0(statement_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.verifyContinuity(ptr0, len0);
    return ret !== 0;
}

/**
 * Checks an identity signature over a device key against the trusted (pinned) identity key.
 * @param {string} user_address
 * @param {string} device_id
 * @param {Uint8Array} device_public_key
 * @param {Uint8Array} signature
 * @param {Uint8Array} trusted_identity_key
 * @returns {boolean}
 */
export function verifyDeviceAttestation(user_address, device_id, device_public_key, signature, trusted_identity_key) {
    const ptr0 = passStringToWasm0(user_address, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(device_id, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(device_public_key, wasm.__wbindgen_export);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(signature, wasm.__wbindgen_export);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passArray8ToWasm0(trusted_identity_key, wasm.__wbindgen_export);
    const len4 = WASM_VECTOR_LEN;
    const ret = wasm.verifyDeviceAttestation(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
    return ret !== 0;
}

/**
 * Checks a device's published share key against its (verified) device key (ENCRYPTION.md §3.1): clients seal
 * nothing to a share key whose signature does not verify.
 * @param {string} device_id
 * @param {Uint8Array} device_public_key
 * @param {Uint8Array} share_public_key
 * @param {Uint8Array} signature
 * @returns {boolean}
 */
export function verifyDeviceShareKey(device_id, device_public_key, share_public_key, signature) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(device_id, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(device_public_key, wasm.__wbindgen_export);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(share_public_key, wasm.__wbindgen_export);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(signature, wasm.__wbindgen_export);
        const len3 = WASM_VECTOR_LEN;
        wasm.verifyDeviceShareKey(retptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return r0 !== 0;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * QR payload `tavrn:verify?v=1&a=…&ka=…&b=…&kb=…` of two users.
 * @param {string} address_a
 * @param {Uint8Array} key_a
 * @param {string} address_b
 * @param {Uint8Array} key_b
 * @returns {string}
 */
export function verifyPayload(address_a, key_a, address_b, key_b) {
    let deferred6_0;
    let deferred6_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(address_a, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(key_a, wasm.__wbindgen_export);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(address_b, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(key_b, wasm.__wbindgen_export);
        const len3 = WASM_VECTOR_LEN;
        wasm.verifyPayload(retptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr5 = r0;
        var len5 = r1;
        if (r3) {
            ptr5 = 0; len5 = 0;
            throw takeObject(r2);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred6_0, deferred6_1, 1);
    }
}

/**
 * True if the payload names exactly the own address with the own key and the contact with the
 * pinned key (FEDERATION.md §10.1).
 * @param {string} text
 * @param {string} own_address
 * @param {Uint8Array} own_key
 * @param {string} contact_address
 * @param {Uint8Array} contact_key
 * @returns {boolean}
 */
export function verifyPayloadMatches(text, own_address, own_key, contact_address, contact_key) {
    const ptr0 = passStringToWasm0(text, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(own_address, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(own_key, wasm.__wbindgen_export);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(contact_address, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passArray8ToWasm0(contact_key, wasm.__wbindgen_export);
    const len4 = WASM_VECTOR_LEN;
    const ret = wasm.verifyPayloadMatches(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
    return ret !== 0;
}

/**
 * Verifies the `signature` of a plaintext message. `fieldsJson` holds the envelope fields
 * (`conversation`, `author`, `device_id`, `reply_to`, `thread_id`, `mentions_everyone`, `mentions`,
 * `attachments`), `contentJcs` the content object in RFC 8785 form (checked against this
 * implementation). Returns false for a wrong signature; throws for malformed input.
 * @param {string} fields_json
 * @param {string} content_jcs
 * @param {string} signature
 * @param {Uint8Array} device_public_key
 * @returns {boolean}
 */
export function verifyPlaintext(fields_json, content_jcs, signature, device_public_key) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(fields_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(content_jcs, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(signature, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(device_public_key, wasm.__wbindgen_export);
        const len3 = WASM_VECTOR_LEN;
        wasm.verifyPlaintext(retptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return r0 !== 0;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Wraps a rotated identity key for the home node (`identity_blob`, 61 bytes).
 * @param {MasterSecret} master
 * @param {IdentityKey} key
 * @param {string} user_address
 * @returns {Uint8Array}
 */
export function wrapIdentityKey(master, key, user_address) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(master, MasterSecret);
        _assertClass(key, IdentityKey);
        const ptr0 = passStringToWasm0(user_address, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        wasm.wrapIdentityKey(retptr, master.__wbg_ptr, key.__wbg_ptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v2 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export4(r0, r1 * 1, 1);
        return v2;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Wraps the master secret for the secret storage method `method` (`recovery` or
 * `passkey:<credential id>`) of `userAddress`; returns the bytes to upload (base64url).
 * @param {MasterSecret} master
 * @param {Uint8Array} wrapping_key
 * @param {string} user_address
 * @param {string} method
 * @returns {Uint8Array}
 */
export function wrapMasterSecret(master, wrapping_key, user_address, method) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(master, MasterSecret);
        const ptr0 = passStringToWasm0(user_address, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(method, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        wasm.wrapMasterSecret(retptr, master.__wbg_ptr, addBorrowedObject(wrapping_key), ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v3 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export4(r0, r1 * 1, 1);
        return v3;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        heap[stack_pointer++] = undefined;
    }
}
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg___wbindgen_is_function_1f9d30630b8b1d3d: function(arg0) {
            const ret = typeof(getObject(arg0)) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_object_3c45d4f2dde4e749: function(arg0) {
            const val = getObject(arg0);
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_90b56bc79aad6f6c: function(arg0) {
            const ret = typeof(getObject(arg0)) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_8865fb403f8fe9d8: function(arg0) {
            const ret = getObject(arg0) === undefined;
            return ret;
        },
        __wbg___wbindgen_string_get_0380ccaa2f57f0d9: function(arg0, arg1) {
            const obj = getObject(arg1);
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_41e9ee4f547fc59a: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_call_187d372bd5fdd4aa: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = getObject(arg0).call(getObject(arg1), getObject(arg2));
            return addHeapObject(ret);
        }, arguments); },
        __wbg_crypto_38df2bab126b63dc: function(arg0) {
            const ret = getObject(arg0).crypto;
            return addHeapObject(ret);
        },
        __wbg_getRandomValues_436a51d0629d84e1: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            getObject(arg0).getRandomValues(getObject(arg1));
        }, arguments); },
        __wbg_length_7f3c00c40364105e: function(arg0) {
            const ret = getObject(arg0).length;
            return ret;
        },
        __wbg_msCrypto_bd5a034af96bcba6: function(arg0) {
            const ret = getObject(arg0).msCrypto;
            return addHeapObject(ret);
        },
        __wbg_new_343a093a3c2ffb4e: function(arg0, arg1) {
            const ret = new Error(getStringFromWasm0(arg0, arg1));
            return addHeapObject(ret);
        },
        __wbg_new_from_slice_9a868026ffa4208a: function(arg0, arg1) {
            const ret = new Uint8Array(getArrayU8FromWasm0(arg0, arg1));
            return addHeapObject(ret);
        },
        __wbg_new_with_length_3da0ad195f6f63ba: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return addHeapObject(ret);
        },
        __wbg_node_84ea875411254db1: function(arg0) {
            const ret = getObject(arg0).node;
            return addHeapObject(ret);
        },
        __wbg_now_aa4ccb83129e9e55: function() {
            const ret = Date.now();
            return ret;
        },
        __wbg_process_44c7a14e11e9f69e: function(arg0) {
            const ret = getObject(arg0).process;
            return addHeapObject(ret);
        },
        __wbg_prototypesetcall_bc27214492979395: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), getObject(arg2));
        },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            getObject(arg0).randomFillSync(takeObject(arg1));
        }, arguments); },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return addHeapObject(ret);
        }, arguments); },
        __wbg_rosterentry_new: function(arg0) {
            const ret = RosterEntry.__wrap(arg0);
            return addHeapObject(ret);
        },
        __wbg_set_name_2c630595dc90a7aa: function(arg0, arg1, arg2) {
            getObject(arg0).name = getStringFromWasm0(arg1, arg2);
        },
        __wbg_static_accessor_GLOBAL_266715b9d96ba635: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_static_accessor_GLOBAL_THIS_10fb7dc1ae063179: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_static_accessor_SELF_0b583911f537483a: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_static_accessor_WINDOW_d7f903d1508cbdc4: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_subarray_002b94d5e13d1411: function(arg0, arg1, arg2) {
            const ret = getObject(arg0).subarray(arg1 >>> 0, arg2 >>> 0);
            return addHeapObject(ret);
        },
        __wbg_versions_276b2795b1c6a219: function(arg0) {
            const ret = getObject(arg0).versions;
            return addHeapObject(ret);
        },
        __wbindgen_generic_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return addHeapObject(ret);
        },
        __wbindgen_generic_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return addHeapObject(ret);
        },
        __wbindgen_object_clone_ref: function(arg0) {
            const ret = getObject(arg0);
            return addHeapObject(ret);
        },
        __wbindgen_object_drop_ref: function(arg0) {
            takeObject(arg0);
        },
    };
    return {
        __proto__: null,
        "./tavrn_crypto_bg.js": import0,
    };
}

const ClientFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_client_free(ptr, 1));
const CommitOutputFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_commitoutput_free(ptr, 1));
const EncryptedContentFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_encryptedcontent_free(ptr, 1));
const EncryptedFileFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_encryptedfile_free(ptr, 1));
const EncryptedShareFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_encryptedshare_free(ptr, 1));
const HandshakeOutcomeFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_handshakeoutcome_free(ptr, 1));
const IdentityKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_identitykey_free(ptr, 1));
const InboxKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_inboxkey_free(ptr, 1));
const MasterSecretFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_mastersecret_free(ptr, 1));
const RecoveryKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_recoverykey_free(ptr, 1));
const RosterEntryFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_rosterentry_free(ptr, 1));
const ShareKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_sharekey_free(ptr, 1));
const VerifyPayloadFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_verifypayload_free(ptr, 1));
const WelcomeJoinFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_welcomejoin_free(ptr, 1));

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
}

function addBorrowedObject(obj) {
    if (stack_pointer == 1) throw new Error('out of js stack');
    heap[--stack_pointer] = obj;
    return stack_pointer;
}

function dropObject(idx) {
    if (idx < 1028) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function getArrayF64FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getFloat64ArrayMemory0().subarray(ptr / 8, ptr / 8 + len);
}

function getArrayJsValueFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    const mem = getDataViewMemory0();
    const result = [];
    for (let i = ptr; i < ptr + 4 * len; i += 4) {
        result.push(takeObject(mem.getUint32(i, true)));
    }
    return result;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

let cachedFloat64ArrayMemory0 = null;
function getFloat64ArrayMemory0() {
    if (cachedFloat64ArrayMemory0 === null || cachedFloat64ArrayMemory0.byteLength === 0) {
        cachedFloat64ArrayMemory0 = new Float64Array(wasm.memory.buffer);
    }
    return cachedFloat64ArrayMemory0;
}

function getStringFromWasm0(ptr, len) {
    return decodeText(ptr >>> 0, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function getObject(idx) { return heap[idx]; }

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        wasm.__wbindgen_export3(addHeapObject(e));
    }
}

let heap = new Array(1024).fill(undefined);
heap.push(undefined, null, true, false);

let heap_next = heap.length;

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passArrayJsValueToWasm0(array, malloc) {
    const ptr = malloc(array.length * 4, 4) >>> 0;
    const mem = getDataViewMemory0();
    for (let i = 0; i < array.length; i++) {
        mem.setUint32(ptr + 4 * i, addHeapObject(array[i]), true);
    }
    WASM_VECTOR_LEN = array.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

let stack_pointer = 1024;

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasmInstance, wasm;
function __wbg_finalize_init(instance, module) {
    wasmInstance = instance;
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedFloat64ArrayMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (!module.ok) {
            throw new Error(`failed to fetch Wasm: ${module.status} ${module.statusText} fetching '${module.url}'`);
        }

        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('tavrn_crypto_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
