# noise-wasm for js-libp2p-noise

Implements the crypto interface used by js-libp2p-noise:
https://github.com/ChainSafe/js-libp2p-noise/blob/master/src/crypto.ts

Allows you to do the crypto operations in WASM.

# Building

```
wasm-pack build --target nodejs --out-dir ./node-noise-wasm
```
