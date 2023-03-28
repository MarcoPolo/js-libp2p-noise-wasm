use core::panic;
use js_sys::{Array, Uint8Array};
use rand_core::{CryptoRng, OsRng, RngCore};
use snow::{
    resolvers::{CryptoResolver, DefaultResolver},
    types::{Cipher, Dh, Random},
};
use std::vec;
use wasm_bindgen::prelude::*;

macro_rules! console_log {
    // Note that this is using the `log` function imported above during
    // `bare_bones`
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

/* Needs to implement this interface:

export interface ICryptoInterface {
  hashSHA256: (data: Uint8Array) => Uint8Array

  getHKDF: (ck: bytes32, ikm: Uint8Array) => Hkdf

  generateX25519KeyPair: () => KeyPair
  generateX25519KeyPairFromSeed: (seed: Uint8Array) => KeyPair
  generateX25519SharedKey: (privateKey: Uint8Array, publicKey: Uint8Array) => Uint8Array

  chaCha20Poly1305Encrypt: (plaintext: Uint8Array, nonce: Uint8Array, ad: Uint8Array, k: bytes32) => bytes
  chaCha20Poly1305Decrypt: (ciphertext: Uint8Array, nonce: Uint8Array, ad: Uint8Array, k: bytes32, dst?: Uint8Array) => bytes | null
}
*/

#[wasm_bindgen]
pub struct Jslibp2pKeyPair {
    publicKey: Vec<u8>,
    privateKey: Vec<u8>,
}

#[wasm_bindgen]
impl Jslibp2pKeyPair {
    #[wasm_bindgen(getter)]
    pub fn publicKey(&self) -> Vec<u8> {
        self.publicKey.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn privateKey(&self) -> Vec<u8> {
        self.privateKey.clone()
    }
}

#[wasm_bindgen]
pub struct CryptoInterfaceImpl {
    resolver: snow::resolvers::DefaultResolver,
    cipher: Box<dyn Cipher>,
    dh: Box<dyn Dh>,
    sha256: Box<dyn snow::types::Hash>,
    out_buf: Vec<u8>,
}

#[wasm_bindgen]
pub struct Tuple3 {
    a: Vec<u8>,
    b: Vec<u8>,
    c: Vec<u8>,
}

#[wasm_bindgen]
impl CryptoInterfaceImpl {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let resolver = DefaultResolver::default();
        let cipher_choice = snow::params::CipherChoice::ChaChaPoly;
        let cipher = resolver.resolve_cipher(&cipher_choice).unwrap();

        let dh = resolver
            .resolve_dh(&snow::params::DHChoice::Curve25519)
            .unwrap();

        let sha256 = resolver
            .resolve_hash(&snow::params::HashChoice::SHA256)
            .unwrap();

        CryptoInterfaceImpl {
            resolver,
            cipher,
            dh,
            sha256,
            out_buf: vec![0; 64 << 10],
        }
    }

    pub fn hashSHA256(&mut self, data: Vec<u8>) -> Vec<u8> {
        let mut out = vec![0; 32];
        self.sha256.reset();
        self.sha256.input(&data);
        self.sha256.result(&mut out);
        return out;
    }

    //   getHKDF: (ck: bytes32, ikm: Uint8Array) => Hkdf
    pub fn getHKDF(&mut self, ck: &[u8], ikm: &[u8]) -> JsValue {
        let mut out1 = vec![0; 32];
        let mut out2 = vec![0; 32];
        let mut out3 = vec![0; 32];

        self.sha256
            .hkdf(ck, ikm, 3, &mut out1, &mut out2, &mut out3);

        let arr = Array::new_with_length(3);
        arr.set(0, Uint8Array::from(out1.as_slice()).into());
        arr.set(1, Uint8Array::from(out2.as_slice()).into());
        arr.set(2, Uint8Array::from(out3.as_slice()).into());
        return arr.into();
    }

    pub fn generateX25519KeyPair(&mut self) -> Jslibp2pKeyPair {
        let mut rng = rand_core::OsRng {};
        self.dh.generate(&mut rng);
        return Jslibp2pKeyPair {
            publicKey: self.dh.pubkey().to_vec(),
            privateKey: self.dh.privkey().to_vec(),
        };
    }
    //   generateX25519KeyPairFromSeed: (seed: Uint8Array) => KeyPair
    pub fn generateX25519KeyPairFromSeed(&mut self, seed: Vec<u8>) -> Jslibp2pKeyPair {
        assert!(seed.len() == 32);
        self.dh.set(&seed);
        return Jslibp2pKeyPair {
            publicKey: self.dh.pubkey().to_vec(),
            privateKey: self.dh.privkey().to_vec(),
        };
    }

    //   generateX25519SharedKey: (privateKey: Uint8Array, publicKey: Uint8Array) => Uint8Array
    pub fn generateX25519SharedKey(
        &mut self,
        private_key: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        self.dh.set(&private_key);
        let mut out = vec![0; 32];
        self.dh.dh(&public_key, &mut out).map_err(|_| "dh failed")?;
        Ok(out)
    }

    pub fn chaCha20Poly1305Encrypt(
        &mut self,
        plaintext: &[u8],
        nonce: &[u8],
        ad: &[u8],
        k: &[u8], // u8;32
    ) -> Vec<u8> {
        self.cipher.set(k);

        let nonce_u64 = u32::from_le_bytes(nonce[4..8].try_into().unwrap()).into();
        let bytes_written = self
            .cipher
            .encrypt(nonce_u64, ad, plaintext, &mut self.out_buf);

        // TODO remove this copy
        self.out_buf[0..bytes_written].to_vec()
    }

    pub fn chaCha20Poly1305Decrypt(
        &mut self,
        ciphertext: &[u8],
        nonce: &[u8],
        ad: &[u8],
        k: &[u8], // u8;32
        _dst: Option<Uint8Array>,
    ) -> Result<Vec<u8>, String> {
        self.cipher.set(k);

        let nonce_u64 = (u32::from_le_bytes(nonce[4..8].try_into().unwrap())).into();
        let bytes_written = self
            .cipher
            .decrypt(nonce_u64, ad, ciphertext, &mut self.out_buf)
            .map_err(|_| "decrypt failed")?;

        // TODO remove this copy
        Ok(self.out_buf[0..bytes_written].to_vec())
    }
}

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    // The `console.log` is quite polymorphic, so we can bind it with multiple
    // signatures. Note that we need to use `js_name` to ensure we always call
    // `log` in JS.
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_u32(a: u32);

    // Multiple arguments too!
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_many(a: &str, b: &str);
}

struct MyRng(rand_core::block::BlockRng<rand_chacha::ChaCha8Core>);
impl RngCore for MyRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}
impl CryptoRng for MyRng {}
impl Random for MyRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
