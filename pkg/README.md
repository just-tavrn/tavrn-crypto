# @tavrn/crypto

The end-to-end encryption core of [tavrn](https://github.com/just-tavrn) (OpenMLS-based MLS client, key
derivation, secret storage, identity verification, sealed boxes for webhooks and history shares, device share
keys, voice frame keys), compiled to WebAssembly
for browsers and Node.js. Built from the Rust crate `tavrn-crypto`; documentation, API overview and build
instructions: <https://github.com/just-tavrn/tavrn-crypto#readme>.

```ts
import init, { Client, MasterSecret } from "@tavrn/crypto";

await init(); // browsers: fetches tavrn_crypto_bg.wasm next to the module
// Node.js: initSync({ module: readFileSync(new URL(import.meta.resolve("@tavrn/crypto/tavrn_crypto_bg.wasm"))) })
```

Most applications use [`@tavrn/e2ee`](https://github.com/just-tavrn/tavrn-js) on top of it.

License: MPL-2.0. Not audited yet.
